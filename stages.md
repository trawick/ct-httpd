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

* Proxy (TLS client): Don't check for SCTs in OCSP responses.
* Add any necessary hooks to mod\_ssl to minimize collision with other
active development, and implement new program logic in mod\_ssl\_ct.
* mod\_ssl\_ct will use certificate-transparency project **executable
files** to communicate with the log(s), avoiding
what looks like a build nightmare.

## Other key decisions

* The interaction with logs can be seen in the filesystem in the form of files for each SCT retrieved from the log as well as the collated form which is sent to clients.  This resulted in a fair amount of gorpy file I/O and directory traversal, but log interaction is easy to observe.  In the future this would presumably be replaced by shared memory and a server-status extension.

## Current status

### First, see the "Issues" section near the top of [src/proto1/mod_ssl_ct.c](https://github.com/trawick/ct-httpd/blob/master/src/proto1/mod_ssl_ct.c).
### Use it like this:

* Build OpenSSL 1.0.2
* Patch httpd trunk with src/proto1/httpd.patch (using OpenSSL 1.0.2)
* Build certificate-transparency tools from https://code.google.com/p/certificate-transparency/
* Build mod\_ssl\_ct with apxs, adding -I/path/to/httpd/modules/ssl and -I/path/to/openssl/include
```
    apxs -ci -I/path/to/httpd/modules/ssl -I/path/to/openssl/include mod_ssl_ct.c ssl_ct_util.c
```
* Configure mod\_ssl\_ct like this:
```
    LoadModule ssl_ct_module modules/mod_ssl_ct.so
    CTLogs http://localhost:8888/ http://otherhost:9999/
    CTAuditStorage /tmp/audit
    CTSCTStorage /tmp/newscts
    CTToolsDir /home/trawick/git/certificate-transparency
    CTMaxSCTAge 3600 # 1 hour
```
* If you want to statically define SCTs to return in addition to those from the log, put them individually in files with extension ".sct" in the directory for the server certificate under CTSCTStorage.  (The SHA1 digest of the server certificate is the directory name.)
* The statuscgi.py CGI script will display "peer-aware" or "peer-unaware" (and a few more standard SSL variables) based on whether or not mod\_ssl\_ct thinks the client understands CT.  (mod\_ssl+mod\_ssl\_ct+mod\_proxy and Chromium from the dev channel are both CT-aware clients.)
