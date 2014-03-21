#!/usr/bin/env python

import re
import time
import urllib2

def last_line(logfile):
    with open(logfile, 'rb') as f:
        # assume that the last line is wholly contained
        # in the last 4K of data
        f.seek(-4096, 2)
        last = f.readlines()[-1]
    return last

def check_log(logfile, peer_status, proxy_sct_sources):
    time.sleep(1)
    log = last_line(logfile)
    regex = 'SSL_CT_PEER_STATUS="([a-z-]*)" SSL_PROXY_SCT_SOURCES="([a-z,]*)"'
    p = re.compile(regex)
    m = p.search(log)
    assert m
    assert m.group(1) == peer_status
    assert m.group(2) == proxy_sct_sources

def test(url, expected_code, echo=False):
    rsp = None
    try:
        req = urllib2.Request(url=url)
        rsp = urllib2.urlopen(req, timeout=10)
    except urllib2.HTTPError as e:
        print 'Failed now: ' + url
        print e.code
        if e.code != expected_code:
            print e.read()
            raise e

    if rsp:
        assert rsp.getcode() == expected_code

    if rsp:
        body = rsp.read()
        if echo:
            print body

access_log = '/home/trawick/inst/ct-64/logs/access_log'
test("http://127.0.0.1:8081/cgi-bin/statuscgi.py", 200, True)
check_log(access_log, 'peer-aware', 'certext,tlsext')
test("http://127.0.0.1:8081/hasocsp/", 500, True)
check_log(access_log, 'peer-unaware', '')
test("http://127.0.0.1:8081/hasocspext/", 200, False)
check_log(access_log, 'peer-aware', 'ocsp')

print ""
print "SUCCESS"