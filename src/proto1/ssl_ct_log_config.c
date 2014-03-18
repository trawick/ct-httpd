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

#include "apr_dbd.h"

#include "httpd.h"
#include "http_log.h"
#include "http_main.h"

#include "ssl_ct_sct.h"
#include "ssl_ct_log_config.h"

int log_config_readable(apr_pool_t *pconf, const char *logconfig,
                        const char **msg)
{
    const apr_dbd_driver_t *driver;
    apr_dbd_t *handle;
    apr_status_t rv;
    apr_dbd_results_t *res;
    int rc;

    rv = apr_dbd_get_driver(pconf, "sqlite3", &driver);
    if (rv != APR_SUCCESS) {
        if (msg) {
            *msg = "SQLite3 driver cannot be loaded";
        }
        return 0;
    }

    rv = apr_dbd_open(driver, pconf, logconfig, &handle);
    if (rv != APR_SUCCESS) {
        return 0;
    }

    /* is there a cheaper way? */
    res = NULL;
    rc = apr_dbd_select(driver, pconf, handle, &res,
                        "SELECT * FROM loginfo WHERE id = 0", 0);

    apr_dbd_close(driver, handle);

    if (rc != 0) {
        return 0;
    }

    return 1;
}

static apr_status_t public_key_cleanup(void *data)
{
    EVP_PKEY *pubkey = data;

    EVP_PKEY_free(pubkey);
    return APR_SUCCESS;
}

static apr_status_t read_public_key(apr_pool_t *p, const char *pubkey_fname,
                                    EVP_PKEY **ppkey)
{
    apr_status_t rv;
    EVP_PKEY *pubkey;
    FILE *pubkeyf;

    *ppkey = NULL;

    pubkeyf = fopen(pubkey_fname, "r");
    if (!pubkeyf) {
        rv = errno; /* Unix-ism! */
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf,
                     "could not open log public key file %s",
                     pubkey_fname);
        return rv;
    }

    pubkey = PEM_read_PUBKEY(pubkeyf, NULL, NULL, NULL);
    if (!pubkey) {
        fclose(pubkeyf);
        rv = APR_EINVAL;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     "PEM_read_PUBKEY() failed to process public key file %s",
                     pubkey_fname);
        return rv;
    }

    fclose(pubkeyf);

    *ppkey = pubkey;

    apr_pool_cleanup_register(p, (void *)pubkey, public_key_cleanup,
                              apr_pool_cleanup_null);

    return APR_SUCCESS;
}

static void digest_public_key(EVP_PKEY *pubkey, unsigned char digest[LOG_ID_SIZE])
{
    int len = i2d_PUBKEY(pubkey, NULL);
    unsigned char *val = malloc(len);
    unsigned char *tmp = val;
    SHA256_CTX sha256ctx;

    ap_assert(LOG_ID_SIZE == SHA256_DIGEST_LENGTH);

    i2d_PUBKEY(pubkey, &tmp);
    SHA256_Init(&sha256ctx);
    SHA256_Update(&sha256ctx, (unsigned char *)val, len);
    SHA256_Final(digest, &sha256ctx);
    free(val);
}

static apr_status_t parse_log_url(apr_pool_t *p, const char *lu, apr_uri_t *puri)
{
    apr_status_t rv;
    apr_uri_t uri;

    rv = apr_uri_parse(p, lu, &uri);
    if (rv == APR_SUCCESS) {
        if (!uri.scheme
            || !uri.hostname
            || !uri.path) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         "Error in log url \"%s\": URL can't be parsed or is missing required "
                         "elements", lu);
            rv = APR_EINVAL;
        }
        if (strcmp(uri.scheme, "http")) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         "Error in log url \"%s\": Only scheme \"http\" (instead of \"%s\") "
                         "is currently accepted",
                         lu, uri.scheme);
            rv = APR_EINVAL;
        }
        if (strcmp(uri.path, "/")) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                         "Error in log url \"%s\": Only path \"/\" (instead of \"%s\") "
                         "is currently accepted",
                         lu, uri.path);
            rv = APR_EINVAL;
        }
    }
    if (rv == APR_SUCCESS) {
        *puri = uri;
    }
    return rv;
}

/* The log_config array should have already been allocated from p. */
apr_status_t save_log_config(apr_array_header_t *log_config,
                             apr_pool_t *p,
                             const char *pubkey_fname,
                             const char *audit_status,
                             const char *url)
{
    apr_status_t rv;
    apr_uri_t uri;
    ct_log_config *newconf, **pnewconf;
    int trusted;
    EVP_PKEY *public_key;

    if (!audit_status) {
        trusted = TRUSTED_UNSET;
    }
    else if (!strcasecmp(audit_status, "F")) {
        trusted = DISTRUSTED;
    }
    else if (!strcasecmp(audit_status, "T")) {
        trusted = TRUSTED;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf,
                     "Audit status \"%s\" not valid", audit_status);
        return APR_EINVAL;
    }

    if (pubkey_fname) {
        rv = read_public_key(p, pubkey_fname, &public_key);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    if (url) {
        rv = parse_log_url(p, url, &uri);
        if (rv != APR_SUCCESS) {
            return rv;
        }
    }

    newconf = apr_pcalloc(p, sizeof(ct_log_config));
    pnewconf = (ct_log_config **)apr_array_push(log_config);
    *pnewconf = newconf;

    newconf->trusted = trusted;
    newconf->public_key = public_key;

    if (newconf->public_key) {
        newconf->log_id = apr_palloc(p, LOG_ID_SIZE);
        digest_public_key(newconf->public_key,
                          (unsigned char *)newconf->log_id);
    }

    newconf->url = url;
    if (url) {
        newconf->uri = uri;
        newconf->uri_str = apr_uri_unparse(p, &uri, 0);
    }
    newconf->public_key_pem = pubkey_fname;

    return APR_SUCCESS;
}

apr_status_t read_config_db(apr_pool_t *p, server_rec *s_main,
                            const char *log_config_fname,
                            apr_array_header_t *log_config)
{
    apr_status_t rv;
    const apr_dbd_driver_t *driver;
    apr_dbd_t *handle;
    apr_dbd_results_t *res;
    apr_dbd_row_t *row;
    int rc;

    ap_assert(log_config);

    rv = apr_dbd_get_driver(p, "sqlite3", &driver);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     "APR SQLite3 driver can't be loaded");
        return rv;
    }

    rv = apr_dbd_open(driver, p, log_config_fname, &handle);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s_main,
                     "Can't open SQLite3 db %s", log_config_fname);
        return rv;
    }

    res = NULL;
    rc = apr_dbd_select(driver, p, handle, &res,
                        "SELECT * FROM loginfo", 0);

    if (rc != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     "SELECT of loginfo records failed");
        apr_dbd_close(driver, handle);
        return APR_EINVAL;
    }

    rc = apr_dbd_num_tuples(driver, res);
    switch (rc) {
    case -1:
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s_main,
                     "Unexpected asynchronous result reading %s",
                     log_config_fname);
        apr_dbd_close(driver, handle);
        return APR_EINVAL;
    case 0:
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s_main,
                     "Log configuration in %s is empty",
                     log_config_fname);
        apr_dbd_close(driver, handle);
        return APR_SUCCESS;
    default:
        /* quiet some lints */
        break;
    }
        
    for (rv = apr_dbd_get_row(driver, p, res, &row, -1);
         rv == APR_SUCCESS;
         rv = apr_dbd_get_row(driver, p, res, &row, -1)) {
        int cur = 0;
        const char *id = apr_dbd_get_entry(driver, row, cur++);
        const char *public_key = apr_dbd_get_entry(driver, row, cur++);
        const char *audit_status = apr_dbd_get_entry(driver, row, cur++);
        const char *url = apr_dbd_get_entry(driver, row, cur++);

        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s_main,
                     "Log config: Record %s, public key file %s, audit status %s, URL %s",
                     id,
                     public_key ? public_key : "(unset)",
                     audit_status ? audit_status : "(unset, defaults to trusted)",
                     url ? url : "(unset)");

        rv = save_log_config(log_config, p,
                             public_key, audit_status, url);
        if (rv != APR_SUCCESS) {
            apr_dbd_close(driver, handle);
            return rv;
        }
    }

    apr_dbd_close(driver, handle);

    return APR_SUCCESS;
}

