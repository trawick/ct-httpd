Development Stages for CT in httpd
==================================

# Prototype 1

## Current stage (Mar ??)

* ??

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

## Other key decisions

* The interaction with logs can be seen in the filesystem in the form of files for each SCT retrieved from the log as well as the collated form which is sent to clients.  This resulted in a fair amount of gorpy file I/O and directory traversal, but log interaction is easy to observe.  In the future this would presumably be replaced by shared memory and a server-status extension.

## Current status

### First, see the "Issues" section near the top of [src/proto1/mod_ssl_ct.c](https://github.com/trawick/ct-httpd/blob/master/src/proto1/mod_ssl_ct.c).
### Use it like this:

* Build OpenSSL 1.0.2-beta1
* Patch httpd trunk with src/proto1/httpd.patch (which has to be built using OpenSSL 1.0.2-beta1)
* If you want to store CT log configuration in a database, which will allow dynamic updates in the future, use a build of APR-Util with SQLite3 database support (--with-sqlite3) **and** use CTLogConfigDB instead of CTStaticLogConfig.
* Build certificate-transparency tools from https://code.google.com/p/certificate-transparency/
* Build mod\_ssl\_ct with apxs, adding -I/path/to/httpd/modules/ssl and -I/path/to/openssl/include
```
    apxs -ci -I/path/to/httpd/modules/ssl -I/path/to/openssl/include mod_ssl_ct.c ssl_ct_util.c ssl_ct_sct.c ssl_ct_log_config.c
```
* Configure mod\_ssl\_ct like this:
```
    LoadModule ssl_ct_module modules/mod_ssl_ct.so
    CTStaticLogConfig - - http://localhost:8888/
    CTStaticLogConfig - - http://otherhost:9999/
    CTStaticLogConfig /path/to/log-public-key.pem - -
    CTAuditStorage /tmp/audit
    CTSCTStorage /tmp/newscts
    CTToolsDir /home/trawick/git/certificate-transparency
    CTMaxSCTAge 3600 # 1 hour
```
* If you want to statically define SCTs to return in addition to those from the log, put them individually in files with extension ".sct" in the directory for the server certificate under CTSCTStorage.  (The SHA256 digest of the server certificate is the directory name.)
* You can configure information about CT logs external to the httpd configuration by using the ctlogconfig program to create a database, and point to the database using the CTLogConfigDB directive.  This requires SQLite3 support in APR-Util.
* The statuscgi.py CGI script will display "peer-aware" or "peer-unaware" (and a few more standard SSL variables) based on whether or not mod\_ssl\_ct thinks the client understands CT.  (mod\_ssl+mod\_ssl\_ct+mod\_proxy and Chromium from the dev channel are both CT-aware clients.)

### Support for off-line auditing of SCTs received by the proxy from servers

* httpd processes queue the server certificate chain and SCTs in a file called audit\_\<PID\>.tmp in the CTAuditStorage directory.  These are flushed and renamed to audit\_\<PID\>.out when the child process exits (MaxConnectionsPerChild, load subsides, restart, stop).
* The individual files for audit, specific to one httpd child process, will not have duplicates (i.e., multiple occurrences of the exact same server certificate/chain and set of SCTs), though there can be duplicates among files for different httpd child processes.
* The off-line audit procedure should move the .out files elsewhere and audit the contents.  These .out files will grow unbounded for the life of the server if the set of unique server certificates + SCTs is unbounded.
* No provision is made for unbounded storage growth due to unbounded numbers of backend servers or unbounded numbers of child processes (each with its own .out file).
* The file contains a series of elements for each server: SERVER_START (0x0001), certificate data (leaf first followed by any intermediate certificates), and SCT data.
* Each certificate is represented by CERT_START (0x0002) and three-byte length followed by the certificate in DER.
* Each SCT is represented by SCT_START (0x0003) and two-byte length followed by the SCT.

### Support for logging what happened

* proxy and server: log the SSL\_CT\_PEER\_STATUS envvar to see if peer is aware
* proxy: log the SSL\_PROXY\_SCT\_SOURCES envvar to see where SCTs came from
