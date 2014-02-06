Development Stages for CT in httpd
==================================

# Prototype 1

## Expected level of functionality

* Web server can obtain SCTs from a statically configured set of logs.
* Web server will log whether or not client is CT-aware.
* Web server will return SCTs when client is CT-aware.
* Proxy will present itself as CT-aware to backend servers.
* Proxy will log information about SCTs (if any) from backend servers.
* Proxy will enqueue server certs/SCTs for audit.

## Implementation shortcuts

* Add any necessary hooks to mod\_ssl to minimize collision with other
active development, and implement new program logic in mod\_ssl\_ct.
* mod\_ssl\_ct will use certificate-transparency project **executable
files** to communicate with the log(s), avoiding
what looks like a build nightmare.

## Current status

### First, see the "Issues" section near the top of [src/proto1/mod_ssl_ct.c](https://github.com/trawick/ct-httpd/blob/master/src/proto1/mod_ssl_ct.c).
### Use it like this:

* Build OpenSSL 1.0.2
* Patch httpd trunk with src/proto1/httpd.patch (using OpenSSL 1.0.2)
* Build certificate-transparency tools from https://code.google.com/p/certificate-transparency/
* Build mod\_ssl\_ct with apxs, but add -I/path/to/httpd/mdoules/ssl and -I/path/to/openssl/include
* Configure mod\_ssl\_ct like this:
```
    LoadModule ssl_ct_module modules/mod_ssl_ct.so
    CTLogs http://localhost:8888/
    CTSCTStorage /tmp/newscts
    CTToolsDir /home/trawick/git/certificate-transparency
```
* The statuscgi.py CGI script will display "peer-aware" or "peer-unaware" (and a few more standard SSL variables) based on whether or not mod\_ssl\_ct thinks the client understands CT.  (mod\_ssl+mod\_ssl\_ct+mod\_proxy and Chromium from the dev channel are both CT-aware clients.)
