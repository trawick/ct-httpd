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
 * * Certificates
 *   These are read to obtain fingerprints and to submit to logs.
 *   The module assumes that they are configured via SSLCertificateFile
 *   with only a leaf certificate in the file.  Certificates loaded by
 *   SSLOpenSSLConfCmd are not supported.
 *
 *   See dev@httpd e-mails discussing SSL_CTX_get_{first,next}_certificate()
 *
 * * Only one SCT can be stored per certificate
 * * SCTs can only be stored at startup
 * * No way to add SCT provided by admin in a file to SCT from log
 *   (Either you use this module and get them from log(s) or you
 *   use SSLOpenSSLConfCmd to configure a file.)
 * * Are we really getting the SCT?  That needs to be tested :)
 * * Proxy flow should queue the server cert and SCT(s) for audit
 *
 * * Configuration kludges
 *   . Can't configure where to store SCTs
 *   . Don't recognize that only one log is supported
 *   . Don't use log URL
 *   . Can't configure where to find certificate-transparency tools
 *
 * * Known low-level code kludges
 *   . uses system() instead of apr_proc_create(), which would allow better
 *     control of output
 *   . no way to log CT-awareness of backend server
 *
 * * Everything else
 *    *
 *
 
 */

#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_mpm.h"

#include "ssl_hooks.h"

#define SCT_BASE_DIR "/tmp/scts"

#define STATUS_VAR "SSL_CT_PEER_STATUS"

/** A certificate file larger than this is suspect */
#define MAX_CERT_FILE_SIZE 30000 /* eventually this can include intermediate certs */

/** Limit on size of stored SCTs for a certificate */
#define MAX_SCTS_SIZE 2000

typedef struct ct_server_config {
    apr_array_header_t *log_urls;
    apr_array_header_t *cert_files;
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
    if (rv == APR_SUCCESS) { /* shouldn't get APR_EOF since we know
                              * how big the file is
                              */
        rv = APR_SUCCESS;
    }
    else {
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

static apr_status_t get_cert_fingerprint_from_file(server_rec *s_main,
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

    rv = readLeafCertificate(s_main, certFile, p,
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

static apr_status_t get_sct(server_rec *s_main, apr_pool_t *p,
                            const char *certFile,
                            const char *logURL, const char *sct_dir)
{
    apr_status_t rv;
    char fingerprint[FINGERPRINT_SIZE];
    char *sct_fn;
    const char *submit_cmd;
    apr_finfo_t finfo;

    rv = get_cert_fingerprint_from_file(s_main, p, certFile, fingerprint,
                                        sizeof fingerprint);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     "failed to get certificate fingerprint from %s",
                     certFile);
        return rv;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main,
                 "fingerprint for %s is %s",
                 certFile, fingerprint);

    rv = apr_filepath_merge(&sct_fn, sct_dir, fingerprint, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     "failed to construct path to SCT for %s", certFile);
        return rv;
    }

    rv = apr_stat(&finfo, sct_fn, APR_FINFO_MIN, p);
    if (rv == APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s_main,
                     "Found SCT for %s in %s",
                     certFile, sct_fn);
        return rv;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, rv, s_main,
                 "Did not find SCT for %s in %s, must fetch",
                 certFile, sct_fn);

    submit_cmd = apr_psprintf(p, "/home/trawick/git/certificate-transparency/src/client/ct --ct_server=localhost:8888 --http_log --logtostderr --ct_server_submission=%s --ct_server_response_out=%s upload",
                              certFile, sct_fn);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s_main,
                 "Running >%s<", submit_cmd);
                              
    rv = system(submit_cmd);

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s_main,
                 "->%d", rv);

    return rv;
}

static int ssl_ct_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s_main)
{
    /* Ensure that we already have, or can fetch, the SCT for each certificate.  
     * If so, start the daemon to maintain these and let startup continue.
     * (Otherwise abort startup.)
     */

    server_rec *s;

    s = s_main;
    while (s) {
        ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                       &ssl_ct_module);
        int i, j;
        apr_status_t rv;
        const char **cert_elts, **log_elts;

        if (sconf && sconf->cert_files) {

            cert_elts = (const char **)sconf->cert_files->elts;
            log_elts  = (const char **)sconf->log_urls->elts;
            for (i = 0; i < sconf->cert_files->nelts; i++) {
                for (j = 0; j < sconf->log_urls->nelts; j++) {
                    rv = get_sct(s_main, pconf, cert_elts[i], log_elts[j],
                                 SCT_BASE_DIR);
                    if (rv != APR_SUCCESS) {
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                }
            }

        }

        s = s->next;
    }

    return OK;
}

static apr_status_t read_scts(apr_pool_t *p, const char *fingerprint,
                              const char *sct_dir,
                              server_rec *s,
                              char **scts, apr_size_t *scts_len)
{
    apr_status_t rv;
    char *sct_fn;

    rv = apr_filepath_merge(&sct_fn, sct_dir, fingerprint, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK,
                     /* this worked at init! */
                     APLOG_CRIT,
                     rv, s,
                     "failed to construct path to SCT for cert with fingerprint %s",
                     fingerprint);
        return rv;
    }

    rv = readFile(p, s, sct_fn, MAX_SCTS_SIZE, scts, scts_len);

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

static const uint16_t CT_EXTENSION_TYPE = 18;
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

    /* need to retrieve SCT from ServerHello */

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "clientExtensionCallback2 called, "
                  "ext %hu was in ServerHello",
                  ext_type);
    ap_log_cdata(APLOG_MARK, APLOG_DEBUG, c, "SCT from ServerHello",
                 in, inlen, AP_LOG_DATA_SHOW_OFFSET);

    return 1;
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
    X509 *x;
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

    x = SSL_get_certificate(ssl);
    get_fingerprint(x, fingerprint, sizeof fingerprint);

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "certificate fingerprint: %s", fingerprint);

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                  "serverExtensionCallback2 called, "
                  "ext %hu will be in ServerHello",
                  ext_type);

    rv = read_scts(c->pool, fingerprint,
                   SCT_BASE_DIR,
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

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "ssl_init_ctx; proxy? %s",
                 is_proxy ? "yes" : "no");

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

static void *create_ct_server_config(apr_pool_t *p, server_rec *s)
{
    ct_server_config *conf =
        (ct_server_config *)apr_pcalloc(p, sizeof(ct_server_config));
    
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

    return conf;
}

static void ct_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(ssl_ct_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(ssl_ct_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_server_init, ssl_ct_ssl_server_init, NULL, NULL, 
                     APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_init_ctx, ssl_ct_ssl_init_ctx, NULL, NULL,
                     APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_new_client_pre_handshake,
                     ssl_ct_ssl_new_client_pre_handshake,
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
        if (!sconf->log_urls) {
            sconf->log_urls = apr_array_make(p, 1, sizeof(uri));
            puri = (apr_uri_t *)apr_array_push(sconf->log_urls);
            *puri = uri;
        }
    }
    return rv;
}

static const char *ct_logs(cmd_parms *cmd, void *x, int argc, char *const argv[])
{
    int i;
    apr_status_t rv;
    ct_server_config *sconf = ap_get_module_config(cmd->server->module_config,
                                                   &ssl_ct_module);
    if (argc < 1) {
        return "At least one log URL must be provided";
    }

    for (i = 0; i < argc; i++) {
        rv = save_log_url(cmd->pool, argv[i], sconf);
        if (rv) {
            return apr_psprintf(cmd->pool, "Error with log URL %s: (%d)%pm",
                                argv[i], rv, &rv);
        }
    }

    return NULL;
}

static const command_rec ct_cmds[] =
{
    AP_INIT_TAKE_ARGV("CTLogs", ct_logs, NULL, RSRC_CONF,
                      "List of Certificate Transparency Log URLs"),
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
