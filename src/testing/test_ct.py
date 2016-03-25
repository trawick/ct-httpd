import locale
import os
import re
import subprocess
import sys
import time

import requests
import yaml

with open('config.yaml') as f:
    config = yaml.load(f)

httpd_inst = config['httpd']['install_root']

cfg = {
    'non-ssl': 'http://127.0.0.1:8081',
    'access-log': os.path.join(httpd_inst, 'logs', 'access_log')
}

# Bug with mod_ssl reporting 502 to mod_proxy; it sets
# 502 in an error bucket but proxy assumes timeout error
STATUS_502_OR_504_RE = re.compile(r'^(502|504)$')

default_non_ssl_requests = (
    # (URI-to-request, expected-status-code, does-client-support-CT, does-backend-support-CT, how-backend-provided-CT)
    ('/', 200, '-', 'peer-aware', 'tlsext'),
    ('/favicon.ico', 404, '-', '-', '-'),
    ('/nosct/', STATUS_502_OR_504_RE, '-', 'peer-unaware', ''),
    ('/hasocspext/', 200, '-', 'peer-aware', 'ocsp'),
    ('/hasocsp/', STATUS_502_OR_504_RE, '-', 'peer-unaware', '')
)

ACCESS_LOG_REGEX = re.compile((
    r'GET (.+) HTTP/1.1" ([0-9]{3}) \d+ SSL_CT_CLIENT_STATUS="([a-z-]*)" '
    r'SSL_CT_PROXY_STATUS="([a-z-]*)" SSL_CT_PROXY_SCT_SOURCES="([a-z,-]*)"'
))


def run_tests(non_ssl_requests):
    print('Testing with server at %s...' % httpd_inst)
    print()
    for path, status, client_status, proxy_status, proxy_sources in non_ssl_requests:
        rsp = requests.get(cfg['non-ssl'] + path)
        print('%s %s %s' % (rsp, rsp.status_code, rsp.reason))

    print()
    time.sleep(2)  # plenty of time for access log to be written

    encoding = locale.getdefaultlocale()[1]
    num_lines = len(non_ssl_requests)
    output = subprocess.check_output(['tail', '-%d' % num_lines, cfg['access-log']]).decode(encoding).split('\n')

    for i in range(len(non_ssl_requests)):
        path, status, client_status, proxy_status, proxy_sources = non_ssl_requests[i]
        print('Request %s:' % path)
        log = output[i]
        m = ACCESS_LOG_REGEX.search(log)
        if m:
            actual_path = m.group(1)
            actual_status = m.group(2)
            actual_client_status = m.group(3)
            actual_proxy_status = m.group(4)
            actual_proxy_sources = m.group(5)

            def compare(what, v1, v2):
                if hasattr(v1, 'match'):
                    mismatch = not v1.match(v2)
                else:
                    mismatch = str(v1) != str(v2)
                if mismatch:
                    print('  Mismatch of %s: expected "%s", got "%s"' % (what, v1, v2))
                    return 1
                return 0

            failures = 0
            failures += compare('path', path, actual_path)
            failures += compare('status', status, actual_status)
            failures += compare('client CT status', client_status, actual_client_status)
            failures += compare('proxy CT status', proxy_status, actual_proxy_status)
            failures += compare('proxy SCT sources', proxy_sources, actual_proxy_sources)
            if not failures:
                print('  ok')
        else:
            print('Unexpected!  Could not match line |%s|' % log, file=sys.stderr)
            sys.exit(1)

    print()
    print('do something manual with with openssl (>=1.0.2) s_client -connect 127.0.0.1:8443 -status -tlsextdebug')
    print('(that won\'t display SCTs; I dunno how to make s_client request it)')


def main():
    try:
        uri = sys.argv[1]
        non_ssl_requests = [x for x in default_non_ssl_requests if x[0] == uri]
    except IndexError:
        non_ssl_requests = default_non_ssl_requests

    if not non_ssl_requests:
        print('No test request found', file=sys.stderr)
        sys.exit(1)

    run_tests(non_ssl_requests)


if __name__ == '__main__':
    main()
