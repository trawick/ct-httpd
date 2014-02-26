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

APLOG_USE_MODULE(ssl_ct);

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

apr_status_t ctutil_run_to_log(apr_pool_t *p,
                               server_rec *s,
                               const char *args[8],
                               const char *desc_for_log)
{
    apr_exit_why_e exitwhy;
    apr_pollfd_t pfd = {0};
    apr_pollset_t *pollset;
    apr_proc_t proc = {0};
    apr_procattr_t *attr;
    apr_status_t rv;
    int exitcode, fds_waiting;

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

    rv = apr_proc_create(&proc, args[0], args, NULL, attr, p);
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

        rv = apr_pollset_poll(pollset, apr_time_from_sec(10),
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
                ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, s,
                             "%s: %.*s", desc_for_log, (int)len, buf);
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
    rv = rv == APR_CHILD_DONE ? APR_SUCCESS : rv;

    ap_log_error(APLOG_MARK,
                 rv != APR_SUCCESS || exitcode ? APLOG_ERR : APLOG_DEBUG,
                 rv, s,
                 "exit code from %s: %d (%s)", 
                 desc_for_log, exitcode,
                 exitwhy == APR_PROC_EXIT ? "exited normally" : "exited due to a signal");

    if (rv == APR_SUCCESS && exitcode) {
        rv = APR_EGENERAL;
    }

    return rv;
}

void ctutil_thread_mutex_lock(apr_thread_mutex_t *m)
{
    apr_status_t rv = apr_thread_mutex_lock(m);
    ap_assert(rv == APR_SUCCESS);
}

void ctutil_thread_mutex_unlock(apr_thread_mutex_t *m)
{
    apr_status_t rv = apr_thread_mutex_unlock(m);
    ap_assert(rv == APR_SUCCESS);
}

apr_status_t ctutil_file_write_uint16(server_rec *s,
                                      apr_file_t *f,
                                      apr_uint16_t in_val)
{
    apr_size_t nbytes;
    apr_status_t rv;
    char vals[2];

    vals[0] = (in_val & 0xFF00) >> 8;
    vals[1] = (in_val & 0x00FF);
    nbytes = sizeof(vals);
    rv = apr_file_write(f, vals, &nbytes);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "can't write 2-byte length to file");
    }
    return rv;
}

void ctutil_log_array(const char *file, int line, int module_index,
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

apr_uint64_t ctutil_deserialize_uint64(const unsigned char *mem)
{
    apr_uint64_t val = 0;
    int i;

    for (i = 0; i < sizeof(val); i++) {
        val = (val << 8) | *mem;
        mem += 1;
    }

    return val;
}

apr_uint16_t ctutil_deserialize_uint16(const unsigned char *mem)
{
    apr_uint16_t val = 0;
    int i;

    for (i = 0; i < sizeof(val); i++) {
        val = (val << 8) | *mem;
        mem += 1;
    }

    return val;
}

/* all this deserialization crap is of course from
 * c-t/src/proto/serializer.cc
 */
static apr_status_t read_u16(unsigned char **mem, apr_size_t *avail, apr_uint16_t *val)
{
    int i;

    if (*avail < 2) {
        return APR_EINVAL;
    }

    *val = 0;

    for (i = 0; i < sizeof(*val); i++) {
        *val = (*val << 8) | **mem;
        *mem += 1;
        *avail -= 1;
    }

    return APR_SUCCESS;
}

static apr_status_t read_length_prefix(unsigned char **mem, apr_size_t *avail,
                                       apr_size_t *result)
{
    apr_status_t rv;
    apr_uint16_t val;

    rv = read_u16(mem, avail, &val);
    if (rv == APR_SUCCESS) {
        *result = val;
    }

    return rv;
}

static apr_status_t read_fixed_bytes(unsigned char **mem, apr_size_t *avail,
                                     apr_size_t len,
                                     unsigned char **start)
{
    if (*avail < len) {
        return APR_EINVAL;
    }

    *start = *mem;
    *avail -= len;
    *mem += len;

    return APR_SUCCESS;
}

apr_status_t ctutil_read_var_bytes(unsigned char **mem, apr_size_t *avail,
                                   unsigned char **start, apr_size_t *len)
{
    apr_status_t rv;

    rv = read_length_prefix(mem, avail, len);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = read_fixed_bytes(mem, avail, *len, start);
    return rv;
}

