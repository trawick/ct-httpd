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

#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "ap_mpm.h"

#include "ssl_private.h"

typedef struct ct_server_config {
    apr_array_header_t *log_urls;
} ct_server_config;

module AP_MODULE_DECLARE_DATA ssl_ct_module;

/* can't apr_proc_create() on request handling thread with threaded MPM
 * on Unix
 */
static int ssl_ct_check_config(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    int forked, threaded;

    rv = ap_mpm_query(AP_MPMQ_IS_FORKED, &forked);
    if (rv == APR_SUCCESS) {
        rv = ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded);
    }

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "MPM query of FORKED or THREADED capability failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (forked != AP_MPMQ_NOT_SUPPORTED && threaded != AP_MPMQ_NOT_SUPPORTED) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "This module does not currently support forked, threaded MPMs like worker or event.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
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

static int ssl_ct_ssl_server_init(server_rec *s, SSLSrvConfigRec *sc)
{
    if (sc->server->pks) {
        SSL_CTX *ctx = sc->server->ssl_ctx;

        X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);

        apr_array_header_t *cert_files = sc->server->pks->cert_files;

        log_array(APLOG_MARK, APLOG_ERR, s, "Certificate files:", cert_files);

    }

    return OK;
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
    AP_OPTIONAL_HOOK(ssl_server_init, ssl_ct_ssl_server_init, NULL, NULL, 
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

module AP_MODULE_DECLARE_DATA ssl_ct_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_ct_server_config,
    merge_ct_server_config,
    ct_cmds,
    ct_register_hooks,
};
