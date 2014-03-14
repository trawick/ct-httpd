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


#include "ssl_ct_sct.h"
#include "ssl_ct_util.h"

#include "http_log.h"

static apr_status_t verify_signature(sct_fields_t *sctf,
                                     EVP_PKEY *pkey)
{
    EVP_MD_CTX ctx;
    int rc;

    if (sctf->signed_data == NULL) {
        return APR_EINVAL;
    }

    EVP_MD_CTX_init(&ctx);
    ap_assert(1 == EVP_VerifyInit(&ctx, EVP_sha256()));
    ap_assert(1 == EVP_VerifyUpdate(&ctx, sctf->signed_data,
                                    sctf->signed_data_len));
    rc = EVP_VerifyFinal(&ctx, sctf->sig, sctf->siglen, pkey);
    EVP_MD_CTX_cleanup(&ctx);

    return rc == 1 ? APR_SUCCESS : APR_EINVAL;
}

apr_status_t sct_verify_signature(conn_rec *c, sct_fields_t *sctf,
                                  apr_array_header_t *log_public_keys,
                                  apr_array_header_t *log_ids)
{
    apr_status_t rv = APR_EINVAL;
    int i;
    EVP_PKEY **pubkey_elts;
    char **logid_elts;
    int nelts = log_public_keys->nelts;

    ap_assert(log_public_keys->nelts == log_ids->nelts);
    ap_assert(sctf->signed_data != NULL);

    pubkey_elts = (EVP_PKEY **)log_public_keys->elts;
    logid_elts = (char **)log_ids->elts;

    for (i = 0; i < nelts; i++) {
        EVP_PKEY *pubkey = pubkey_elts[i];
        char *logid = logid_elts[i];

        if (!memcmp(logid, sctf->logid, LOG_ID_SIZE)) {
            rv = verify_signature(sctf, pubkey);
            if (rv != APR_SUCCESS) {
                ap_log_cerror(APLOG_MARK, 
                              APLOG_ERR,
                              rv, c,
                              "verify_signature failed");
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                              "verify_signature succeeded");
            }
            return rv;
        }
    }

    return APR_NOTFOUND;
}

apr_status_t sct_parse(const char *source,
                       server_rec *s, const unsigned char *sct,
                       apr_size_t len, cert_chain *cc,
                       sct_fields_t *fields)
{
    const unsigned char *cur;
    apr_size_t orig_len = len;
    apr_status_t rv;

    memset(fields, 0, sizeof *fields);

    if (len < 1 + LOG_ID_SIZE + 8) {
        /* no room for header */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SCT size %" APR_SIZE_T_FMT " is too small",
                     len);
        return APR_EINVAL;
    }

    cur = sct;

    fields->version = *cur;
    cur++;
    len -= 1;
    memcpy(fields->logid, cur, LOG_ID_SIZE);
    cur += LOG_ID_SIZE;
    len -= LOG_ID_SIZE;
    rv = ctutil_deserialize_uint64(&cur, &len, &fields->timestamp);
    ap_assert(rv == APR_SUCCESS);

    fields->time = apr_time_from_msec(fields->timestamp);

    /* XXX maybe do this only if log level is such that we'll
     *     use it later?
     */
    apr_rfc822_date(fields->timestr, fields->time);


    if (len < 2) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SCT size %" APR_SIZE_T_FMT " has no space for extension "
                     "len", orig_len);
        return APR_EINVAL;
    }

    rv = ctutil_deserialize_uint16(&cur, &len, &fields->extlen);
    ap_assert(rv == APR_SUCCESS);

    if (fields->extlen != 0) {
        if (fields->extlen < len) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "SCT size %" APR_SIZE_T_FMT " has no space for "
                         "%hu bytes of extensions",
                         orig_len, fields->extlen);
            return APR_EINVAL;
        }

        fields->extensions = cur;
        cur += fields->extlen;
        len -= fields->extlen;
    }
    else {
        fields->extensions = 0;
    }

    if (len < 4) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SCT size %" APR_SIZE_T_FMT " has no space for "
                     "hash algorithm, signature algorithm, and signature len",
                     orig_len);
        return APR_EINVAL;
    }

    fields->hash_alg = *cur;
    cur += 1;
    len -= 1;
    fields->sig_alg = *cur;
    cur += 1;
    len -= 1;
    rv = ctutil_deserialize_uint16(&cur, &len, &fields->siglen);
    ap_assert(rv == APR_SUCCESS);

    if (fields->siglen < len) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "SCT has no space for signature");
        return APR_EINVAL;
    }

    fields->sig = cur;
    cur += fields->siglen;
    len -= fields->siglen;

    fields->signed_data = NULL;
    fields->signed_data_len = 0;

    if (cc) {
        /* If we have the server certificate, we can construct the
         * data over which the signature is computed.
         */

        /* XXX Which part is signed? */
        /* See certificate-transparency/src/proto/serializer.cc,
         * method Serializer::SerializeV1CertSCTSignatureInput()
         */

        apr_size_t orig_len = 1000000;
        apr_size_t avail = orig_len;
        unsigned char *mem = malloc(avail);
        unsigned char *orig_mem = mem;

        rv = ctutil_serialize_uint8(&mem, &avail, 0); /* version 1 */
        if (rv == APR_SUCCESS) {
            rv = ctutil_serialize_uint8(&mem, &avail, 0); /* CERTIFICATE_TIMESTAMP */
        }
        if (rv == APR_SUCCESS) {
            rv = ctutil_serialize_uint64(&mem, &avail, fields->timestamp);
        }
        if (rv == APR_SUCCESS) {
            rv = ctutil_serialize_uint16(&mem, &avail, 0); /* X509_ENTRY */
        }
        if (rv == APR_SUCCESS) {
            /* Get DER encoding of leaf certificate */
            unsigned char *der_buf
                /* get OpenSSL to allocate: */
                = NULL;
            int der_length;

            der_length = i2d_X509(cc->leaf, &der_buf);
            if (der_length < 0) {
                rv = APR_EINVAL;
            }
            else {
                rv = ctutil_write_var24_bytes(&mem, &avail,
                                              der_buf, der_length);
                OPENSSL_free(der_buf);
            }
        }
        if (rv == APR_SUCCESS) {
            rv = ctutil_write_var16_bytes(&mem, &avail, fields->extensions,
                                          fields->extlen);
                                          
        }

        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                         "Failed to reconstruct signed data for SCT");
            free(orig_mem);
        }
        else {
            fields->signed_data_len = orig_len - avail;
            fields->signed_data = orig_mem;
            /* Force invalid signature error: orig_mem[0] = orig_mem[0] + 1; */
        }
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "SCT from %s: version %d timestamp %s hash alg %d sig alg %d",
                 source, fields->version, fields->timestr,
                 fields->hash_alg, fields->sig_alg);
#if AP_MODULE_MAGIC_AT_LEAST(20130702,2)
    ap_log_data(APLOG_MARK, APLOG_DEBUG, s, "Log Id",
                fields->logid, sizeof(fields->logid),
                AP_LOG_DATA_SHOW_OFFSET);
    ap_log_data(APLOG_MARK, APLOG_DEBUG, s, "Signature",
                fields->sig, fields->siglen,
                AP_LOG_DATA_SHOW_OFFSET);
#endif /* httpd has ap_log_*data() */

    return rv;
}

apr_status_t sct_verify_timestamp(conn_rec *c, sct_fields_t *sctf)
{
    if (sctf->time > apr_time_now()) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "Server sent SCT not yet valid (timestamp %s)",
                      sctf->timestr);
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}
