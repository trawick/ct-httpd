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
 * A. Certificates
 *    These are read to obtain fingerprints and to submit to logs.
 *    The module assumes that they are configured via SSLCertificateFile
 *    with only a leaf certificate in the file.  Certificates loaded by
 *    SSLOpenSSLConfCmd are not supported.
 *
 */

#include "apr_hash.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_mpm.h"

#include "ssl_hooks.h"

#define STATUS_VAR "SSL_CT_PEER_STATUS"

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

static apr_hash_t *sct_hash;

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

/* can't apr_proc_create() on request handling thread with threaded MPM
 * on Unix
 */
static int ssl_ct_check_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    sct_hash = apr_hash_make(pconf);

    return OK;
}

/* As of httpd 2.5, this should only read the FIRST certificate
 * in the file.  NOT IMPLEMENTED (assumes that the leaf certificate
 * is the ONLY certificate)
 */
static void readLeafCertificate(server_rec *s,
                                const char *fn, apr_pool_t *p,
                                const char **leafCert, apr_size_t *leafCertSize)
{
    /* Uggg...  For now assume that only a leaf certificate is in the PEM file. */
    apr_file_t *f;
    apr_status_t rv;
    char *buf;
    apr_size_t nbytes, bytes_read;

    *leafCert = NULL;
    *leafCertSize = 0;
    rv = apr_file_open(&f, fn, APR_READ | APR_BINARY, APR_FPROT_OS_DEFAULT, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "couldn't read %s", fn);
        return;
    }

    if (rv == APR_SUCCESS) {
        nbytes = 50000;
        buf = apr_palloc(p, nbytes);
        rv = apr_file_read_full(f, buf, nbytes, &bytes_read);
        if (rv == APR_EOF) {
            *leafCert = buf;
            *leafCertSize = bytes_read;
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                         "apr_file_read_full");
        }
        apr_file_close(f);
    }
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
    int i;
    const char **elts;
    ct_server_config *sconf = ap_get_module_config(s->module_config,
                                                   &ssl_ct_module);
#if 0
    X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);
#endif

    log_array(APLOG_MARK, APLOG_INFO, s, "Certificate files:", cert_files);
    sconf->cert_files = cert_files;

    elts = (const char **)sconf->cert_files->elts;
    for (i = 0; i < sconf->cert_files->nelts; i++) {
        /* Get fingerprint of certificate for association with SCTs. */
        const char *fn = elts[i];
        char fingerprint[FINGERPRINT_SIZE];
        BIO *bio;
        X509 *x;
        const char *leafCert;
        apr_size_t leafCertSize;

        readLeafCertificate(s, fn, s->process->pool, &leafCert, &leafCertSize);

        if (leafCert) {
            bio = BIO_new_mem_buf((void *)leafCert, leafCertSize);
            x = PEM_read_bio_X509(bio, NULL, 0L, NULL);
            ap_assert(x);
            get_fingerprint(x, fingerprint, sizeof fingerprint);
            apr_hash_set(sct_hash, apr_pstrdup(s->process->pool, fingerprint),
                         APR_HASH_KEY_STRING, "GARBAGE!!!");
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                         "fingerprint for %s: %s (%s)",
                         fn, fingerprint,
                         (char *)apr_hash_get(sct_hash, fingerprint, APR_HASH_KEY_STRING));
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "leaf certificate couldn't be read from %s", fn);
        }        
    }

    return OK;
}

static int ssl_ct_ssl_new_client(server_rec *s, conn_rec *c)
{
    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c, "client connected");
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
    const unsigned char *sct;

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

    /* need to get the real SCT(s) */
    sct = (const unsigned char *)apr_hash_get(sct_hash, fingerprint,
                                              APR_HASH_KEY_STRING);
    if (sct) {
        *out = sct;
    }
    else {
        *out = (const unsigned char *)"NO SCT!";
    }
    *outlen = (unsigned short)(strlen((const char *)*out) + 1);

    return 1;
}

static void tlsext_cb(SSL *ssl, int client_server, int type,
                      unsigned char *data, int len,
                      void *arg)
{
    conn_rec *c = arg;

#if 0
    ap_log_cerror(APLOG_MARK, APLOG_TRACE8, 0, c, "tlsext_cb called (%d,%d,%d)",
                  client_server, type, len);
#endif

    if (type == CT_EXTENSION_TYPE) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, "Got CT extension");

        client_is_ct_aware(c);
    }
}

static int ssl_ct_ssl_new_client_pre(server_rec *s, conn_rec *c, SSL *ssl)
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
    ap_hook_check_config(ssl_ct_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(ssl_ct_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_server_init, ssl_ct_ssl_server_init, NULL, NULL, 
                     APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_new_client, ssl_ct_ssl_new_client, NULL, NULL,
                     APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_init_ctx, ssl_ct_ssl_init_ctx, NULL, NULL,
                     APR_HOOK_MIDDLE);
    AP_OPTIONAL_HOOK(ssl_new_client_pre, ssl_ct_ssl_new_client_pre, NULL, NULL,
                     APR_HOOK_MIDDLE);
}

static const char *ct_peek_certificatefile(cmd_parms *cmd,
                                           void *dcfg,
                                           const char *arg)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
                 "Certificate file: %s", arg);
    return NULL;
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
    AP_INIT_TAKE1("SSLCertificateFile", ct_peek_certificatefile, NULL, RSRC_CONF,
                  "xxxxx"),
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
