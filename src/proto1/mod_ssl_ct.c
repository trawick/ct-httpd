/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Issues
 *
 * + Certificates
 *   These are read to obtain fingerprints and to submit to logs.
 *   The module assumes that they are configured via SSLCertificateFile
 *   with only a leaf certificate in the file.  Certificates loaded by
 *   SSLOpenSSLConfCmd are not supported.
 *
 *   See dev@httpd e-mails discussing SSL_CTX_get_{first,next}_certificate()
 *
 *   Ah, but the log needs to see intermediate certificates too...
 * 
dr* + Are we really sending the SCT(s) correctly?  That needs to be tested in
 *   detail.  But the TLS client used by mod_proxy needs some minimal verification
 *   implemented anyway.
 * + Proxy flow should queue the server cert and SCT(s) for audit in a manner
 *   that facilitates the auditing support in the c-t tools.
 * + Proxy should have a setting that aborts when the backend doesn't send
 *   an SCT.  (It must recognize when one is delivered with the certificate
 *   or via OCSP stapling.)
 *
 * + Configuration kludges
 *   . ??
 *
 * + Known low-level code kludges/problems
 *   . no way to log CT-awareness of backend server (put it in configurable response
 *     header to allow logging or easy testing from client)
 *   . no way to automatically get rid of stored sct for log which is no
 *     longer used/respected
 *
 * + Everything else
 *   . ??
 *
 * + Stuff to remember, or note elsewhere:
 *   .
 *
 */

#if !defined(WIN32)
#define HAVE_SCT_DAEMON
#else
/* SCTs from logs or from admin-created .sct files are only picked up
 * at server start/restart.
 */
#endif

#if !defined(WIN32) && defined(HAVE_SCT_DAEMON)
#include <unistd.h>
#endif

#include "apr_global_mutex.h"
#include "apr_signal.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_mutex.h"
#include "ap_mpm.h"

#include "ssl_hooks.h"

#ifdef WIN32
#define DOTEXE ".exe"
#else
#define DOTEXE ""
#endif

#define STATUS_VAR          "SSL_CT_PEER_STATUS"

#define DAEMON_NAME         "SCT maintenance daemon"
#define SERVICE_THREAD_NAME "service thread"

/** A certificate file larger than this is suspect */
#define MAX_CERT_FILE_SIZE 30000 /* eventually this can include intermediate certs */

/** Limit on size of stored SCTs for a certificate (individual SCTs as well
 * as size of all.
 */
#define MAX_SCTS_SIZE 10000

typedef struct ct_server_config {
    apr_array_header_t *log_urls;
    apr_array_header_t *cert_files;
    const char *sct_storage;
    const char *ct_tools_dir;
    const char *ct_exe;
    apr_time_t max_sct_age;
} ct_server_config;

typedef struct ct_conn_config {
    int peer_ct_aware;
} ct_conn_config;

typedef struct ct_callback_info {
    server_rec *s;
    conn_rec *c;
    ct_conn_config *conncfg;
} ct_callback_info;

module AP_MODULE_DECLARE_DATA ssl_ct_module;

#define SSL_CT_MUTEX_TYPE "ssl-ct-sct-update"

static apr_global_mutex_t *ssl_ct_sct_update;

static int refresh_all_scts(server_rec *s_main, apr_pool_t *p);

static apr_thread_t *service_thread;

#ifdef HAVE_SCT_DAEMON

/* The APR other-child API doesn't tell us how the daemon exited
 * (SIGSEGV vs. exit(1)).  The other-child maintenance function
 * needs to decide whether to restart the daemon after a failure
 * based on whether or not it exited due to a fatal startup error
 * or something that happened at steady-state.  This exit status
 * is unlikely to collide with exit signals.
 */
#define DAEMON_STARTUP_ERROR 254

static int daemon_start(apr_pool_t *p, server_rec *main_server, apr_proc_t *procnew);
static server_rec *root_server = NULL;
static apr_pool_t *root_pool = NULL;
static apr_pool_t *pdaemon = NULL;
static pid_t daemon_pid;
static int daemon_should_exit = 0;

#endif /* HAVE_SCT_DAEMON */

#define FINGERPRINT_SIZE 60

static void get_fingerprint(X509 *x, char *fingerprint, size_t fpsize)
{
    const EVP_MD *digest;
    unsigned char md[EVP_MAX_MD_SIZE];
    int i;
    unsigned int n;
    digest = EVP_get_digestbyname("sha1");
    X509_digest(x, digest, md, &n);

    ap_assert(n == 20);
    ap_assert(fpsize >= FINGERPRINT_SIZE);

    i = 0;
    while (i < n - 1) {
        apr_snprintf(fingerprint + i * 3, 4, "%02X:", md[i]);
        i++;
    }
    apr_snprintf(fingerprint + i * 3, 3, "%02X", md[i]);
}

static int dir_exists(apr_pool_t *p, const char *dirname)
{
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, dirname, APR_FINFO_TYPE, p);

    return rv == APR_SUCCESS && finfo.filetype == APR_DIR;
}

static int file_exists(apr_pool_t *p, const char *filename)
{
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, filename, APR_FINFO_TYPE, p);

    return rv == APR_SUCCESS && finfo.filetype == APR_REG;
}

static apr_status_t readFile(apr_pool_t *p,
                             server_rec *s,
                             const char *fn,
                             apr_size_t limit,
                             char **contents,
                             apr_size_t *contents_size)
{
    apr_file_t *f;
    apr_finfo_t finfo;
    apr_status_t rv;
    apr_size_t nbytes;

    *contents = NULL;
    *contents_size = 0;

    rv = apr_file_open(&f, fn, APR_READ | APR_BINARY, APR_FPROT_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "couldn't read %s", fn);
        return rv;
    }
    
    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, f);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "couldn't retrieve size of %s", fn);
        apr_file_close(f);
        return rv;
    }

    if (finfo.size > limit) {
        rv = APR_ENOSPC;
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "size of %s exceeds limit", fn);
        apr_file_close(f);
        return rv;
    }

    nbytes = (apr_size_t)finfo.size;
    *contents = apr_palloc(p, nbytes);
    rv = apr_file_read_full(f, *contents, nbytes, contents_size);
    if (rv != APR_SUCCESS) { /* shouldn't get APR_EOF since we know
                              * how big the file is
                              */
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "apr_file_read_full");
    }
    apr_file_close(f);

    return rv;
}

/* As of httpd 2.5, this should only read the FIRST certificate
 * in the file.  NOT IMPLEMENTED (assumes that the leaf certificate
 * is the ONLY certificate)
 */
static apr_status_t readLeafCertificate(server_rec *s,
                                        const char *fn, apr_pool_t *p,
                                        const char **leafCert, 
                                        apr_size_t *leafCertSize)
{
    apr_status_t rv;

    /* Uggg...  For now assume that only a leaf certificate is in the PEM file. */

    rv = readFile(p, s, fn, MAX_CERT_FILE_SIZE, (char **)leafCert,
                  leafCertSize);

    return rv;
}

static apr_status_t get_cert_fingerprint_from_file(server_rec *s,
                                                   apr_pool_t *p,
                                                   const char *certFile,
                                                   char *fingerprint,
                                                   size_t fingerprint_size)
{
    apr_status_t rv;
    BIO *bio;
    X509 *x;
    const char *leafCert;
    apr_size_t leafCertSize;

    rv = readLeafCertificate(s, certFile, p,
                             &leafCert, &leafCertSize);

    if (rv == APR_SUCCESS) {
        bio = BIO_new_mem_buf((void *)leafCert, leafCertSize);
        ap_assert(bio);
        x = PEM_read_bio_X509(bio, NULL, 0L, NULL);
        ap_assert(x);
        get_fingerprint(x, fingerprint, fingerprint_size);
    }

    return rv;
}

/* SCT storage on disk:
 *
 *   <rootdir>/<fingerprint>/hostname_port_uri.sct   SCT for cert with this fingerprint
 *                                                   from this log (could be any number
 *                                                   of these)
 *   <rootdir>/<fingerprint>/<anything>.sct          SCT maintained by the administrator
 *                                                   (file is optional; could be any number
 *                                                   of these)
 *   <rootdir>/<fingerprint>/collated                one or more SCTs ready to send
 *                                                   (this is all that the web server
 *                                                   processes care about)
 *
 * Bug: no automatic way to get rid of .sct files from logs we no longer respect
 */

#define COLLATED_SCTS_BASENAME "collated"

static apr_status_t collate_scts(server_rec *s, apr_pool_t *p,
                                 const char *cert_sct_dir)
{
    /* Read the various .sct files and stick them together in a single file */
    apr_dir_t *d;
    apr_status_t rv;
    apr_finfo_t finfo;
    char *tmp_collated_fn, *collated_fn, *cur_sct_file;
    apr_file_t *tmpfile;

    rv = apr_filepath_merge(&collated_fn, cert_sct_dir, COLLATED_SCTS_BASENAME, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "can't build path based on %s", cert_sct_dir);
        return rv;
    }

    /* Note: We rebuild the file that combines the SCTs every time this
     *       code runs, even if no individual SCTs are new (or at least
     *       re-fetched).
     *       That allows the admin to see the last processing by looking
     *       at the timestamp.
     */
    tmp_collated_fn = apr_pstrcat(p, collated_fn, ".tmp", NULL);

    rv = apr_file_open(&tmpfile, tmp_collated_fn,
                       APR_FOPEN_WRITE|APR_FOPEN_CREATE|APR_FOPEN_TRUNCATE|APR_FOPEN_BINARY,
                       APR_FPROT_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "can't create %s", tmp_collated_fn);
        return rv;
    }

    rv = apr_dir_open(&d, cert_sct_dir, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "couldn't read dir %s",
                     cert_sct_dir);
        return rv;
    }

    while ((rv = apr_dir_read(&finfo, APR_FINFO_MTIME|APR_FINFO_NAME, d)) == APR_SUCCESS) {
        /* only care about files which end in ".sct" */
        size_t len = strlen(finfo.name);
        char *scts;
        apr_size_t scts_size, bytes_written;

        if (len < strlen("X.sct")) {
            continue;
        }

        if (strcmp(finfo.name + len - 4, ".sct")) {
            continue;
        }

        rv = apr_filepath_merge(&cur_sct_file, cert_sct_dir, finfo.name, 0, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "can't build filename from %s and %s",
                         cert_sct_dir, finfo.name);
            break;
        }

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                     "Adding SCT from file %s", finfo.name);

        rv = readFile(p, s, cur_sct_file, MAX_SCTS_SIZE, &scts, &scts_size);
        if (rv != APR_SUCCESS) {
            break;
        }

        rv = apr_file_write_full(tmpfile, scts, scts_size, &bytes_written);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "can't write %" APR_SIZE_T_FMT " bytes to %s",
                         scts_size, tmp_collated_fn);
            break;
        }
    }

    if (rv == APR_ENOENT) {
        rv = APR_SUCCESS;
    }
    else if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "couldn't read dir %s",
                     cert_sct_dir);
    }

    apr_file_close(tmpfile);
    apr_dir_close(d);

    if (rv == APR_SUCCESS) {
        int replacing = file_exists(p, collated_fn);

        if (replacing) {
            if ((rv = apr_global_mutex_lock(ssl_ct_sct_update)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             "global mutex lock failed");
                return rv;
            }
            apr_file_remove(collated_fn, p);
        }
        rv = apr_file_rename(tmp_collated_fn, collated_fn, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "couldn't rename %s to %s",
                         tmp_collated_fn, collated_fn);
            if (replacing) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             "continuing to use existing file %s",
                             collated_fn);
            }
        }
        if (replacing) {
            if ((rv = apr_global_mutex_unlock(ssl_ct_sct_update)) != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             "global mutex unlock failed");
            }
        }
    }

    return rv;
}

static const char *url_to_fn(apr_pool_t *p, const apr_uri_t *logURL)
{
    char *fn = apr_psprintf(p, "%s_%s_%s.sct",
                            logURL->hostname, logURL->port_str, logURL->path);
    char *ch;

    ch = fn;
    while (*ch) {
        switch(*ch) {
        /* chars that shouldn't be used in a filename */
        case ':':
        case '/':
            *ch = '-';
        }
        ++ch;
    }
    return fn;
}

static apr_status_t get_cert_sct_dir(server_rec *s, apr_pool_t *p,
                                     const char *certFile,
                                     const char *sct_dir,
                                     char **cert_sct_dir_out)
{
    apr_status_t rv;
    char fingerprint[FINGERPRINT_SIZE];
    char *cert_sct_dir;

    *cert_sct_dir_out = NULL;

    rv = get_cert_fingerprint_from_file(s, p, certFile, fingerprint,
                                        sizeof fingerprint);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "failed to get certificate fingerprint from %s",
                     certFile);
        return rv;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "fingerprint for %s is %s",
                 certFile, fingerprint);

    rv = apr_filepath_merge(&cert_sct_dir, sct_dir, fingerprint, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "failed to construct path to SCT for %s", certFile);
        return rv;
    }

    *cert_sct_dir_out = cert_sct_dir;
    return APR_SUCCESS;
}

static apr_status_t submission(server_rec *s, apr_pool_t *p, const char *ct_exe,
                               const apr_uri_t *logURL, const char *certFile,
                               const char *sct_fn)
{
    apr_pollfd_t pfd = {0};
    apr_pollset_t *pollset;
    apr_proc_t proc = {0};
    apr_procattr_t *attr;
    apr_status_t rv;
    apr_exit_why_e exitwhy;
    const char *args[8];
    int exitcode, fds_waiting, i;

    i = 0;
    args[i++] = ct_exe;
    args[i++] = apr_pstrcat(p, "--ct_server=", logURL->hostinfo, NULL);
    args[i++] = "--http_log";
    args[i++] = "--logtostderr";
    args[i++] = apr_pstrcat(p, "--ct_server_submission=", certFile, NULL);
    args[i++] = apr_pstrcat(p, "--ct_server_response_out=", sct_fn, NULL);
    args[i++] = "upload";
    args[i++] = NULL;
    ap_assert(i == sizeof args / sizeof args[0]);

    rv = apr_procattr_create(&attr, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "apr_procattr_create failed");
        return rv;
    }

    rv = apr_procattr_io_set(attr,
                             APR_NO_PIPE,
                             APR_CHILD_BLOCK,
                             APR_CHILD_BLOCK);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "apr_procattr_io_set failed");
        return rv;
    }

    rv = apr_proc_create(&proc, ct_exe, args, NULL, attr, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "apr_proc_create failed");
        return rv;
    }

#if APR_FILES_AS_SOCKETS
    rv = apr_pollset_create(&pollset, 2, p, 0);
    ap_assert(rv == APR_SUCCESS);

    fds_waiting = 0;

    pfd.p = p;
    pfd.desc_type = APR_POLL_FILE;
    pfd.reqevents = APR_POLLIN;
    pfd.desc.f = proc.err;
    rv = apr_pollset_add(pollset, &pfd);
    ap_assert(rv == APR_SUCCESS);
    ++fds_waiting;

    pfd.desc.f = proc.out;
    rv = apr_pollset_add(pollset, &pfd);
    ap_assert(rv == APR_SUCCESS);
    ++fds_waiting;

    while (fds_waiting) {
        int i, num_events;
        const apr_pollfd_t *pdesc;
        char buf[4096];
        apr_size_t len;

        rv = apr_pollset_poll(pollset, apr_time_from_sec(1),
                              &num_events, &pdesc);
        if (rv != APR_SUCCESS && !APR_STATUS_IS_EINTR(rv)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "apr_pollset_poll");
            break;
        }

        for (i = 0; i < num_events; i++) {
            len = sizeof buf;
            rv = apr_file_read(pdesc[i].desc.f, buf, &len);
            if (APR_STATUS_IS_EOF(rv)) {
                apr_file_close(pdesc[i].desc.f);
                apr_pollset_remove(pollset, &pdesc[i]);
                --fds_waiting;
            }
            else if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                             "apr_file_read");
            }
            else {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, 
                             "output from log client: %.*s", (int)len, buf);
            }
        }
    }
#else
#error Implement a different type of I/O loop for Windows.
    /* See mod_ext_filter for code for !APR_FILES_AS_SOCKETS which
     * services two pipes using a timeout and non-blocking handles.
     */
#endif

    rv = apr_proc_wait(&proc, &exitcode, &exitwhy, APR_WAIT);
    rv = rv == APR_CHILD_DONE ? 0 : rv;

    ap_log_error(APLOG_MARK, APLOG_INFO, rv, s,
                 "->exit code %d  exitwhy %d", exitcode, exitwhy);

    return rv;
}

static apr_status_t fetch_sct(server_rec *s, apr_pool_t *p,
                              const char *certFile,
                              const char *cert_sct_dir,
                              const apr_uri_t *logURL, const char *sct_dir,
                              const char *ct_exe, apr_time_t max_sct_age)
{
    apr_status_t rv;
    char *sct_fn;
    apr_finfo_t finfo;
    const char *logURL_basename;

    logURL_basename = url_to_fn(p, logURL);

    rv = apr_filepath_merge(&sct_fn, cert_sct_dir, logURL_basename, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "failed to construct path to SCT for %s (log fn %s)",
                     certFile, logURL_basename);
        return rv;
    }

    rv = apr_stat(&finfo, sct_fn, APR_FINFO_MTIME, p);
    if (rv == APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                     "Found SCT for %s in %s",
                     certFile, sct_fn);

        if (finfo.mtime + max_sct_age < apr_time_now()) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                         "Older than %d seconds, must refresh",
                         (int)(apr_time_sec(max_sct_age)));
        }
        else {
            return APR_SUCCESS;
        }
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO,
                     /* no need to print error string for file-not-found err */
                     APR_STATUS_IS_ENOENT(rv) ? 0 : rv,
                     s,
                     "Did not find SCT for %s in %s, must fetch",
                     certFile, sct_fn);
    }

    rv = submission(s, p, ct_exe, logURL, certFile, sct_fn);

    return rv;
}

static apr_status_t refresh_scts_for_cert(server_rec *s, apr_pool_t *p,
                                          const char *cert_fn,
                                          const char *sct_dir,
                                          apr_array_header_t *log_urls,
                                          const char *ct_exe,
                                          apr_time_t max_sct_age)
{
    apr_status_t rv;
    apr_uri_t *log_elts;
    char *cert_sct_dir;
    int i;

    log_elts  = (apr_uri_t *)log_urls->elts;

    rv = get_cert_sct_dir(s, p, cert_fn, sct_dir, &cert_sct_dir);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    if (!dir_exists(p, cert_sct_dir)) {
        rv = apr_dir_make(cert_sct_dir, APR_FPROT_OS_DEFAULT, p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "can't create directory %s",
                         cert_sct_dir);
            return rv;
        }
    }

    for (i = 0; i < log_urls->nelts; i++) {
        rv = fetch_sct(s, p, cert_fn,
                       cert_sct_dir,
                       &log_elts[i],
                       sct_dir,
                       ct_exe,
                       max_sct_age);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    rv = collate_scts(s, p, cert_sct_dir);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return rv;
}

static void *run_service_thread(apr_thread_t *me, void *data)
{
    server_rec *s = data;
    int mpmq_s;
    apr_status_t rv;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 SERVICE_THREAD_NAME " started");

    while (1) {
        if ((rv = ap_mpm_query(AP_MPMQ_MPM_STATE, &mpmq_s)) != APR_SUCCESS) {
            break;
        }
        if (mpmq_s == AP_MPMQ_STOPPING) {
            break;
        }
        apr_sleep(apr_time_from_sec(1));
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, s,
                 SERVICE_THREAD_NAME " exiting");

    return NULL;
}

static apr_status_t wait_for_service_thread(void *data)
{
    apr_thread_t *thd = data;
    apr_status_t retval;

    apr_thread_join(&retval, thd);
    return APR_SUCCESS;
}

#ifdef HAVE_SCT_DAEMON

static void daemon_signal_handler(int sig)
{
    if (sig == SIGHUP) {
        ++daemon_should_exit;
    }
}

#if APR_HAS_OTHER_CHILD
static void daemon_maint(int reason, void *data, apr_wait_t status)
{
    apr_proc_t *proc = data;
    int mpm_state;
    int stopping;

    switch (reason) {
        case APR_OC_REASON_DEATH:
            apr_proc_other_child_unregister(data);
            /* If apache is not terminating or restarting,
             * restart the daemon
             */
            stopping = 1; /* if MPM doesn't support query,
                           * assume we shouldn't restart daemon
                           */
            if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS &&
                mpm_state != AP_MPMQ_STOPPING) {
                stopping = 0;
            }
            if (!stopping) {
                if (status == DAEMON_STARTUP_ERROR) {
                    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf, APLOGNO(01238)
                                 DAEMON_NAME " failed to initialize");
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(01239)
                                 DAEMON_NAME " process died, restarting");
                    daemon_start(root_pool, root_server, proc);
                }
            }
            break;
        case APR_OC_REASON_RESTART:
            /* don't do anything; server is stopping or restarting */
            apr_proc_other_child_unregister(data);
            break;
        case APR_OC_REASON_LOST:
            /* Restart the child cgid daemon process */
            apr_proc_other_child_unregister(data);
            daemon_start(root_pool, root_server, proc);
            break;
        case APR_OC_REASON_UNREGISTER:
            /* we get here when pcgi is cleaned up; pcgi gets cleaned
             * up when pconf gets cleaned up
             */
            kill(proc->pid, SIGHUP); /* send signal to daemon telling it to die */
            break;
    }
}
#endif

static int sct_daemon(server_rec *s_main)
{
    apr_status_t rv;
    apr_pool_t *ptemp;

    apr_signal(SIGCHLD, SIG_IGN);
    apr_signal(SIGHUP, daemon_signal_handler);

    rv = apr_global_mutex_child_init(&ssl_ct_sct_update,
                                     apr_global_mutex_lockfile(ssl_ct_sct_update), pdaemon);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, root_server,
                     "could not initialize " SSL_CT_MUTEX_TYPE
                     " mutex in " DAEMON_NAME);
        return DAEMON_STARTUP_ERROR;
    }

    /* ptemp - temporary pool for refresh cycles */
    apr_pool_create(&ptemp, pdaemon);

    while (!daemon_should_exit) {
        apr_sleep(apr_time_from_sec(30));

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main,
                     DAEMON_NAME " - refreshing SCTs as needed");
        rv = refresh_all_scts(s_main, ptemp);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                         DAEMON_NAME " - SCT refresh failed; will try again later");
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main,
                 DAEMON_NAME " - exiting");

    return 0;
}

static int daemon_start(apr_pool_t *p, server_rec *main_server,
                        apr_proc_t *procnew)
{
    daemon_should_exit = 0; /* clear setting from previous generation */
    if ((daemon_pid = fork()) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, main_server,
                     "Couldn't create " DAEMON_NAME " process");
        return DECLINED;
    }
    else if (daemon_pid == 0) {
        if (pdaemon == NULL) {
            apr_pool_create(&pdaemon, p);
        }
        exit(sct_daemon(main_server) > 0 ? DAEMON_STARTUP_ERROR : -1);
    }
    procnew->pid = daemon_pid;
    procnew->err = procnew->in = procnew->out = NULL;
    apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);
#if APR_HAS_OTHER_CHILD
    apr_proc_other_child_register(procnew, daemon_maint, procnew, NULL, p);
#endif
    return OK;
}

#endif /* HAVE_SCT_DAEMON */

static apr_status_t ssl_ct_mutex_remove(void *data)
{
    apr_global_mutex_destroy(ssl_ct_sct_update);
    ssl_ct_sct_update = NULL;
    return APR_SUCCESS;
}

static int refresh_all_scts(server_rec *s_main, apr_pool_t *p)
{
    apr_status_t rv;
    server_rec *s;

    s = s_main;
    while (s) {
        ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                       &ssl_ct_module);
        int i;
        const char **cert_elts;
 
        if (sconf && sconf->cert_files) {
            cert_elts = (const char **)sconf->cert_files->elts;
            for (i = 0; i < sconf->cert_files->nelts; i++) {
                rv = refresh_scts_for_cert(s_main, p, cert_elts[i],
                                           sconf->sct_storage, sconf->log_urls,
                                           sconf->ct_exe,
                                           sconf->max_sct_age);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
            }
        }

        s = s->next;
    }

    return rv;
}

static int ssl_ct_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s_main)
{
    apr_status_t rv;

#ifdef HAVE_SCT_DAEMON
    apr_proc_t *procnew = NULL;
    const char *userdata_key = "sct_daemon_init";
    void *data;

    root_server = s_main;
    root_pool = pconf;

    apr_pool_userdata_get(&data, userdata_key, s_main->process->pool);
    if (!data) {
        procnew = apr_pcalloc(s_main->process->pool, sizeof(*procnew));
        procnew->pid = -1;
        procnew->err = procnew->in = procnew->out = NULL;
        apr_pool_userdata_set((const void *)procnew, userdata_key,
                              apr_pool_cleanup_null, s_main->process->pool);
    }
    else {
        procnew = data;
    }
#endif /* HAVE_SCT_DAEMON */

    rv = ap_global_mutex_create(&ssl_ct_sct_update, NULL,
                                SSL_CT_MUTEX_TYPE, NULL, s_main, pconf, 0);
    if (rv != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_cleanup_register(pconf, (void *)s_main, ssl_ct_mutex_remove,
                              apr_pool_cleanup_null);

    /* Ensure that we already have, or can fetch, fresh SCTs for each 
     * certificate.  If so, start the daemon to maintain these and let
     * startup continue.  (Otherwise abort startup.)
     */

    rv = refresh_all_scts(s_main, pconf);
    if (rv != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#ifdef HAVE_SCT_DAEMON
    if (ap_state_query(AP_SQ_MAIN_STATE) != AP_SQ_MS_CREATE_PRE_CONFIG) {
        int ret = daemon_start(pconf, s_main, procnew);
        if (ret != OK) {
            return ret;
        }
    }
#endif /* HAVE_SCT_DAEMON */

    return OK;
}

static int ssl_ct_check_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s_main)
{
    ct_server_config *sconf = ap_get_module_config(s_main->module_config,
                                                   &ssl_ct_module);

    if (!sconf->sct_storage) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     "Directive CTSCTStorage is required");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!sconf->ct_tools_dir) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     "Directive CTToolsDir is required");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}

static apr_status_t read_scts(apr_pool_t *p, const char *fingerprint,
                              const char *sct_dir,
                              server_rec *s,
                              char **scts, apr_size_t *scts_len)
{
    apr_status_t rv, tmprv;
    char *cert_dir, *sct_fn;

    rv = apr_filepath_merge(&cert_dir, sct_dir, fingerprint, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK,
                     /* this worked at init! */
                     APLOG_CRIT,
                     rv, s,
                     "failed to construct path to SCT for cert with fingerprint %s",
                     fingerprint);
        return rv;
    }

    rv = apr_filepath_merge(&sct_fn, cert_dir, COLLATED_SCTS_BASENAME, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK,
                     /* this worked at init! */
                     APLOG_CRIT,
                     rv, s,
                     "failed to construct path to SCT for cert with fingerprint %s",
                     fingerprint);
        return rv;
    }

    if ((rv = apr_global_mutex_lock(ssl_ct_sct_update)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "global mutex lock failed");
        return rv;
    }

    rv = readFile(p, s, sct_fn, MAX_SCTS_SIZE, scts, scts_len);

    if ((tmprv = apr_global_mutex_unlock(ssl_ct_sct_update)) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, tmprv, s,
                     "global mutex unlock failed");
    }

    return rv;
}

static void log_array(const char *file, int line, int module_index,
                      int level, server_rec *s, const char *desc,
                      apr_array_header_t *arr)
{
    const char **elts = (const char **)arr->elts;
    int i;

    ap_log_error(file, line, module_index, level,
                 0, s, "%s", desc);
    for (i = 0; i < arr->nelts; i++) {
        ap_log_error(file, line, module_index, level,
                     0, s, ">>%s", elts[i]);
    }
}

static int ssl_ct_ssl_server_init(server_rec *s, SSL_CTX *ctx, apr_array_header_t *cert_files)
{
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);
#if 0
    X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);
#endif

    log_array(APLOG_MARK, APLOG_INFO, s, "Certificate files:", cert_files);
    sconf->cert_files = cert_files;

    return OK;
}

static void client_is_ct_aware(conn_rec *c)
{
    ct_conn_config *conncfg =
      ap_get_module_config(c->conn_config, &ssl_ct_module);

    if (!conncfg) {
        conncfg = apr_pcalloc(c->pool, sizeof *conncfg);
        ap_set_module_config(c->conn_config, &ssl_ct_module, conncfg);
    }

    conncfg->peer_ct_aware = 1;
}

static int is_client_ct_aware(conn_rec *c)
{
    ct_conn_config *conncfg =
      ap_get_module_config(c->conn_config, &ssl_ct_module);

    return conncfg && conncfg->peer_ct_aware;
}

/* Look at SSLClient::VerifyCallback() and WriteSSLClientCTData()
 * for validation and saving of data for auditing in a form that
 * the c-t tools can use.
 */

/* Enqueue data from server for off-line audit (cert, SCT(s))
 * Make a simple effort to avoid re-enqueueing the same data in
 * order to save space.  (With reverse proxy it will be the same
 * data over and over.)
 */
static void save_server_data(conn_rec *c, const X509 *peer_cert,
                             const char *scts, apr_size_t scts_size)
{
}

/* XXX
 * perform quick sanity check of server SCT(s) during handshake;
 * errors should result in fatal alert
 */
static apr_status_t validate_server_data(conn_rec *c, const X509 *peer_cert,
                                         const char *scts, apr_size_t scts_size)
{
    return APR_SUCCESS;
}

/* signed_certificate_timestamp */
static const unsigned short CT_EXTENSION_TYPE = 18;

/* Callbacks and structures for handling custom TLS Extensions:
 *   cli_ext_first_cb  - sends data for ClientHello TLS Extension
 *   cli_ext_second_cb - receives data from ServerHello TLS Extension
 */
static int clientExtensionCallback1(SSL *ssl, unsigned short ext_type,
                                    const unsigned char **out,
                                    unsigned short *outlen, void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);

    /* nothing to send in ClientHello */

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "clientExtensionCallback1 called, "
                  "ext %hu will be in ClientHello",
                  ext_type);

    return 1;
}

static int clientExtensionCallback2(SSL *ssl, unsigned short ext_type,
                                    const unsigned char *in, unsigned short inlen,
                                    int *al, void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);

    /* need to retrieve SCT(s) from ServerHello (or certificate or stapled response) */

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "clientExtensionCallback2 called, "
                  "ext %hu was in ServerHello",
                  ext_type);
    ap_log_cdata(APLOG_MARK, APLOG_DEBUG, c, "SCT(s) from ServerHello",
                 in, inlen, AP_LOG_DATA_SHOW_OFFSET);

    /* Note: Peer certificate is not available in this callback via
     *       SSL_get_peer_certificate(ssl)
     */

    return 1;
}

static int ssl_ct_ssl_proxy_verify(server_rec *s, conn_rec *c, SSL *ssl,
                                   X509_STORE_CTX *ctx)
{
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "ssl_ct_ssl_proxy_verify() - get server certificate info");

#if 0
    if (!peer_cert) {
        ap_log_cerror(APLOG_MARK, APLOG_CRIT, 0, c,
                      "clientExtensionCallback2 called, no peer cert available!");
        /* return fatal alert???? */
    }

    if (peer_cert) {
        if (validate_server_data(c, peer_cert, (const char *)in, inlen) != APR_SUCCESS) {
            /* return fatal alert???? */
        }

        save_server_data(c, peer_cert, (const char *)in, inlen);
        X509_free(peer_cert);
    }
#endif

    return APR_SUCCESS;
}

static int serverExtensionCallback1(SSL *ssl, unsigned short ext_type,
                                    const unsigned char *in,
                                    unsigned short inlen, int *al,
                                    void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);

    /* this callback tells us that client is CT-aware;
     * there's nothing of interest in the extension data
     */
    client_is_ct_aware(c);

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "serverExtensionCallback1 called, "
                  "ext %hu was in ClientHello (len %hu)",
                  ext_type, inlen);

    return 1;
}

static int serverExtensionCallback2(SSL *ssl, unsigned short ext_type,
                                    const unsigned char **out,
                                    unsigned short *outlen, void *arg)
{
    conn_rec *c = (conn_rec *)SSL_get_app_data(ssl);
    ct_server_config *sconf = ap_get_module_config(c->base_server->module_config,
                                                   &ssl_ct_module);
    X509 *server_cert;
    char fingerprint[FINGERPRINT_SIZE];
    const unsigned char *scts;
    apr_size_t scts_len;
    apr_status_t rv;

    if (!is_client_ct_aware(c)) {
        /* Hmmm...  Is this actually called if the client doesn't include
         * the extension in the ClientHello?  I don't think so.
         */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      "serverExtensionCallback2: client isn't CT-aware");
        /* Skip this extension for ServerHello */
        return -1;
    }

    /* need to reply with SCT */

    server_cert = SSL_get_certificate(ssl); /* no need to free! */
    get_fingerprint(server_cert, fingerprint, sizeof fingerprint);

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "certificate fingerprint: %s", fingerprint);

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "serverExtensionCallback2 called, "
                  "ext %hu will be in ServerHello",
                  ext_type);

    rv = read_scts(c->pool, fingerprint,
                   sconf->sct_storage,
                   c->base_server, (char **)&scts, &scts_len);
    if (rv == APR_SUCCESS) {
        *out = scts;
        *outlen = scts_len;
    }
    else {
        /* Skip this extension for ServerHello */
        return -1;
    }

    return 1;
}

static void tlsext_cb(SSL *ssl, int client_server, int type,
                      unsigned char *data, int len,
                      void *arg)
{
    conn_rec *c = arg;

#if 0
    /* so noisy, even for TRACE8 */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "tlsext_cb called (%d,%d,%d)",
                  client_server, type, len);
#endif

    if (type == CT_EXTENSION_TYPE) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Got CT extension");

        client_is_ct_aware(c);
    }
}

static int ssl_ct_ssl_new_client_pre_handshake(server_rec *s, conn_rec *c, SSL *ssl)
{
    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, "client connected (pre-handshake)");

    /* This callback is needed only to determine that the peer is CT-aware
     * when resuming a session.  For an initial handshake, the callbacks
     * registered via SSL_CTX_set_custom_srv_ext() are sufficient.
     */
    SSL_set_tlsext_debug_callback(ssl, tlsext_cb);
    SSL_set_tlsext_debug_arg(ssl, c);

    return OK;
}

static int ssl_ct_ssl_init_ctx(server_rec *s, apr_pool_t *p, apr_pool_t *ptemp, int is_proxy, SSL_CTX *ssl_ctx)
{
    ct_callback_info *cbi = apr_pcalloc(p, sizeof *cbi);

    cbi->s = s;

    if (is_proxy) {
        /* _cli_ = "client"
         *
         * Even though the callbacks don't do anything, this is sufficient to
         * include the CT extension in the ClientHello
         */
        if (!SSL_CTX_set_custom_cli_ext(ssl_ctx, CT_EXTENSION_TYPE,
                                        clientExtensionCallback1,
                                        clientExtensionCallback2, cbi)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         "Unable to initalize Certificate Transparency client "
                         "extension callbacks (callback for %d already registered?)",
                         CT_EXTENSION_TYPE);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else {
        /* _srv_ = "server"
         *
         * Even though the callbacks don't do anything, this is sufficient to
         * include the CT extension in the ServerHello
         */
        if (!SSL_CTX_set_custom_srv_ext(ssl_ctx, CT_EXTENSION_TYPE,
                                        serverExtensionCallback1,
                                        serverExtensionCallback2, cbi)) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                         "Unable to initalize Certificate Transparency server "
                         "extension callback (callbacks for %d already registered?)",
                         CT_EXTENSION_TYPE);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

static int ssl_ct_post_read_request(request_rec *r)
{
    ct_conn_config *conncfg =
      ap_get_module_config(r->connection->conn_config, &ssl_ct_module);

    if (conncfg && conncfg->peer_ct_aware) {
        apr_table_set(r->subprocess_env, STATUS_VAR, "peer-aware");
    }
    else {
        apr_table_set(r->subprocess_env, STATUS_VAR, "peer-unaware");
    }

    return DECLINED;
}

static int ssl_ct_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp)
{
    apr_status_t rv = ap_mutex_register(pconf, SSL_CT_MUTEX_TYPE, NULL,
                                        APR_LOCK_DEFAULT, 0);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return OK;
}

static void ssl_ct_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    rv = apr_global_mutex_child_init(&ssl_ct_sct_update,
                                     apr_global_mutex_lockfile(ssl_ct_sct_update), p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "could not initialize " SSL_CT_MUTEX_TYPE
                     " mutex in child");
        return;
    }

    rv = apr_thread_create(&service_thread, NULL, run_service_thread, s, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                     "could not create " SERVICE_THREAD_NAME " in child");
        return;
    }

    apr_pool_cleanup_register(p, service_thread, wait_for_service_thread,
                              apr_pool_cleanup_null);
}

static void *create_ct_server_config(apr_pool_t *p, server_rec *s)
{
    ct_server_config *conf =
        (ct_server_config *)apr_pcalloc(p, sizeof(ct_server_config));

    conf->max_sct_age = apr_time_from_sec(3600);
    
    return conf;
}

static void *merge_ct_server_config(apr_pool_t *p, void *basev, void *virtv)
{
    ct_server_config *base = (ct_server_config *)basev;
    ct_server_config *virt = (ct_server_config *)virtv;
    ct_server_config *conf;

    conf = (ct_server_config *)apr_pmemdup(p, virt, sizeof(ct_server_config));

    conf->log_urls = (virt->log_urls != NULL)
        ? virt->log_urls
        : base->log_urls;

    conf->sct_storage = base->sct_storage;
    conf->ct_tools_dir = base->ct_tools_dir;
    conf->max_sct_age = base->max_sct_age;

    return conf;
}

static void ct_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(ssl_ct_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(ssl_ct_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(ssl_ct_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(ssl_ct_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(ssl_ct_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_server_init, ssl_ct_ssl_server_init, NULL, NULL, 
                     APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_init_ctx, ssl_ct_ssl_init_ctx, NULL, NULL,
                     APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_new_client_pre_handshake,
                     ssl_ct_ssl_new_client_pre_handshake,
                     NULL, NULL, APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_proxy_verify, ssl_ct_ssl_proxy_verify,
                     NULL, NULL, APR_HOOK_MIDDLE);
}

static apr_status_t save_log_url(apr_pool_t *p, const char *lu, ct_server_config *sconf)
{
    apr_status_t rv;
    apr_uri_t uri, *puri;

    rv = apr_uri_parse(p, lu, &uri);
    if (rv == APR_SUCCESS) {
        if (!uri.scheme
            || !uri.hostname
            || !uri.path) {
            rv = APR_EINVAL;
        }
        if (strcmp(uri.scheme, "http")) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "Scheme must be \"http\" instead of \"%s\"",
                         uri.scheme);
            rv = APR_EINVAL;
        }
        if (strcmp(uri.path, "/")) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "No URI path other than \"/\" is currently accepted (you have \"%s\")",
                         uri.path);
            rv = APR_EINVAL;
        }
        if (!sconf->log_urls) {
            sconf->log_urls = apr_array_make(p, 2, sizeof(uri));
        }
        puri = (apr_uri_t *)apr_array_push(sconf->log_urls);
        *puri = uri;
    }
    return rv;
}

static const char *ct_logs(cmd_parms *cmd, void *x, int argc, char *const argv[])
{
    int i;
    apr_status_t rv;
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }

    if (argc < 1) {
        return "CTLogs: At least one log URL must be provided";
    }

    for (i = 0; i < argc; i++) {
        rv = save_log_url(cmd->pool, argv[i], sconf);
        if (rv) {
            return apr_psprintf(cmd->pool, "CTLogs: Error with log URL %s: (%d)%pm",
                                argv[i], rv, &rv);
        }
    }

    return NULL;
}

static const char *ct_sct_storage(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }

    if (!dir_exists(cmd->pool, arg)) {
        return apr_pstrcat(cmd->pool, "CTSCTStorage: Directory ", arg,
                           " does not exist", NULL);
    }

    sconf->sct_storage = arg;

    return NULL;
}

static const char *ct_tools_dir(cmd_parms *cmd, void *x, const char *arg)
{
    apr_status_t rv;
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err) {
        return err;
    }

    if (!dir_exists(cmd->pool, arg)) {
        return apr_pstrcat(cmd->pool, "CTToolsDir: Directory ", arg,
                           " does not exist", NULL);
    }

    rv = apr_filepath_merge((char **)&sconf->ct_exe, arg,  "src/client/ct" DOTEXE,
                            0, cmd->pool);
    if (rv != APR_SUCCESS) {
        return apr_psprintf(cmd->pool,
                            "CTToolsDir: Couldn't build path to ct" DOTEXE
                            ": %pm", &rv);
    }

    if (!file_exists(cmd->pool, sconf->ct_exe)) {
        return apr_pstrcat(cmd->pool, "CTToolsDir: File ", sconf->ct_exe,
                           " does not exist", NULL);
    }

    sconf->ct_tools_dir = arg;

    return NULL;
}

static const char *ct_max_sct_age(cmd_parms *cmd, void *x, const char *arg)
{
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    long val;
    char *endptr;

    if (err) {
        return err;
    }

    errno = 0;
    val = strtol(arg, &endptr, 10);
    if (errno != 0
        || *endptr != '\0'
        || val < 10
        || val > 3600 * 12) {
        return apr_psprintf(cmd->pool, "CTMaxSCTAge must be between 10 seconds "
                            "and 12 hours worth of seconds (%d)",
                            3600 * 12);
    }
    sconf->max_sct_age = apr_time_from_sec(val);
    return NULL;
}    

static const command_rec ct_cmds[] =
{
    AP_INIT_TAKE_ARGV("CTLogs", ct_logs, NULL, RSRC_CONF,
                      "List of Certificate Transparency Log URLs"),
    AP_INIT_TAKE1("CTSCTStorage", ct_sct_storage, NULL, RSRC_CONF,
                  "Location to store SCTs obtained from logs"),
    AP_INIT_TAKE1("CTToolsDir", ct_tools_dir, NULL, RSRC_CONF,
                  "Location of certificate-transparency.org tools"),
    AP_INIT_TAKE1("CTMaxSCTAge", ct_max_sct_age, NULL, RSRC_CONF,
                  "Max age of SCT obtained from log before refresh"),
    {NULL}
};

AP_DECLARE_MODULE(ssl_ct) =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_ct_server_config,
    merge_ct_server_config,
    ct_cmds,
    ct_register_hooks,
};
