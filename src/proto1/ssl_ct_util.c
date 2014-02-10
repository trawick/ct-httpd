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

#include "apr_fnmatch.h"
#include "apr_lib.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_log.h"

#include "ssl_ct_util.h"

apr_status_t ctutil_path_join(char **out, const char *dirname, const char *basename,
                              apr_pool_t *p, server_rec *s)
{
    apr_status_t rv;

    rv = apr_filepath_merge(out, dirname, basename, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "can't build filename from %s and %s",
                     dirname, basename);
    }

    return rv;
}

int ctutil_dir_exists(apr_pool_t *p, const char *dirname)
{
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, dirname, APR_FINFO_TYPE, p);

    return rv == APR_SUCCESS && finfo.filetype == APR_DIR;
}

int ctutil_file_exists(apr_pool_t *p, const char *filename)
{
    apr_finfo_t finfo;
    apr_status_t rv = apr_stat(&finfo, filename, APR_FINFO_TYPE, p);

    return rv == APR_SUCCESS && finfo.filetype == APR_REG;
}

void ctutil_buffer_to_array(apr_pool_t *p, const char *b,
                            apr_size_t b_size, apr_array_header_t **out)
{
    apr_array_header_t *arr = apr_array_make(p, 10, sizeof(char *));
    const char *ch, *last;

    ch = b;
    last = b + b_size - 1;
    while (ch < last) {
        const char *end = memchr(ch, '\n', last - ch);
        const char *line;

        if (!end) {
            end = last + 1;
        }
        while (apr_isspace(*ch) && ch < end) {
            ch++;
        }
        if (ch < end) {
            const char *tmpend = end - 1;

            while (tmpend > ch
                   && isspace(*tmpend)) {
                --tmpend;
            }
            
            line = apr_pstrndup(p, ch, 1 + tmpend - ch);
            *(const char **)apr_array_push(arr) = line;
        }
        ch = end + 1;
    }

    *out = arr;
}

int ctutil_in_array(const char *needle, const apr_array_header_t *haystack)
{
    const char * const *elts;
    int i;

    elts = (const char * const *)haystack->elts;
    for (i = 0; i < haystack->nelts; i++) {
        if (!strcmp(needle, elts[i])) {
            return 1;
        }
    }

    return 0;
}

/* read_dir() is remarkably like apr_match_glob(), which could
 * probably use some processing flags to indicate variations on
 * the basic behavior (and implement better error checking).
 */
apr_status_t ctutil_read_dir(apr_pool_t *p,
                             server_rec *s,
                             const char *dirname,
                             const char *pattern,
                             apr_array_header_t **outarr)
{
    apr_array_header_t *arr;
    apr_dir_t *d;
    apr_finfo_t finfo;
    apr_status_t rv;
    int reported = 0;

    *outarr = NULL;
    arr = apr_array_make(p, 4, sizeof(char *));

    rv = apr_dir_open(&d, dirname, p);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "couldn't read dir %s",
                     dirname);
        return rv;
    }

    while ((rv = apr_dir_read(&finfo, APR_FINFO_NAME, d)) == APR_SUCCESS) {
        const char *fn;

        if (APR_SUCCESS == apr_fnmatch(pattern, finfo.name, APR_FNM_CASE_BLIND)) {
            rv = ctutil_path_join((char **)&fn, dirname, finfo.name, p, s);
            if (rv != APR_SUCCESS) {
                reported = 1;
                break;
            }

            *(char **)apr_array_push(arr) = apr_pstrdup(p, fn);
        }
    }

    if (rv == APR_ENOENT) {
        rv = APR_SUCCESS;
    }
    else if (rv != APR_SUCCESS && !reported) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "couldn't read entry from dir %s", dirname);
    }

    apr_dir_close(d);

    if (rv == APR_SUCCESS) {
        *outarr = arr;
    }

    return rv;
}

apr_status_t ctutil_read_file(apr_pool_t *p,
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
                     "size %" APR_OFF_T_FMT " of %s exceeds limit (%"
                     APR_SIZE_T_FMT ")", finfo.size, fn, limit);
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

