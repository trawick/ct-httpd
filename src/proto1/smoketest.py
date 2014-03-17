#!/usr/bin/env python

import urllib2

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

test("http://127.0.0.1:8081/cgi-bin/statuscgi.py", 200, True)
test("http://127.0.0.1:8081/hasocsp/", 500, True)
test("http://127.0.0.1:8081/hasocspext/", 200, False)

print ""
print "SUCCESS"
