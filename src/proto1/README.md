Log configuration overview
==========================

The following information can be configured for a log:

* public key
* URL
* audit status

Partial information can be provided.  Any number of logs may be described.

This information can be configured statically in the httpd configuration, or configured in a SQLite3 database which is read by httpd at intervals.

The SQLite3 database is maintained by a command-line program (ctlogconfig).

## Configuration issues

* The public key is currently configured as the name of a file containing the PEM encoding of the key, so the PEM file has to exist with the same lifetime as the configuration in order to use that.  It may be more useful to store the DER encoding of the public key directly in the database, while allowing the administrator to specify a PEM or DER-formatted file to be read.
* The log id, which is the SHA-256 hash of the DER form of the log's public key, cannot currently be configured directly.  That would be the most convenient way to identify a log which is untrusted.

## Use of log configuration by server mode

Server mode is concerned primarily with the URL of the log.  For each log URL found in the configuration (other than those marked as having failed audit), server certificates will be submitted to the log and the SCTs received will be sent to clients in the ServerHello once their timestamp is valid.

## Use of log configuration by proxy mode

Proxy mode uses the public key in order to verify the signature of SCTs it receives.

Proxy mode checks the audit status of a log to determine if an SCT is from a log known to be untrusted.

SCT configuration
=================

The primary sources of SCTs sent to clients in server mode are

* received from logs for which a URL is configured
* included in a certificate extension
* included in the stapled OCSP response

In addition, the administrator can statically configure one or more SCTs for a particular server certificate.  This is configured by storing an SCT in a file with extension .sct in the SCT directory for a certificate.

The base SCT directory is configured with the CTSCTStorage directive, and the certificate-specific directory name is the lower-case hex encoding of the SHA-256 hash of the DER form of the server leaf certificate.  This directory will contain SCTs received from configured logs, as well as any SCTs stored by the administrator.

Server processing overview
==========================

Basically the server wants to send SCTs to the client.  SCTs in a certificate extension or stapled OCSP response will be sent without any special program logic.  The new processing handles sending SCTs configured by the administrator or received from known logs in the ServerHello.

For each server certificate, a daemon process maintains an SCT list to be sent in the ServerHello, created from statically configured SCTs as well as those received from logs.  Logs marked as untrusted will be ignored.  Periodically the daemon will submit certificates to a log as necessary (due to changed log configuration or age) and rebuild the concatenation of SCTs.

The SCT list for a server certificate will be sent to any client that indicates awareness in the ClientHello when that particular server certificate is used.

Proxy processing overview
=========================

The proxy indicates CT awareness in the ClientHello by including the signed\_certificate\_timestamp extension.  It can recognize SCTs received in the ServerHello, in an extension in the server certificate, or on a stapled OCSP response.

On-line verification is attempted for each received SCT:

* for any SCT, the timestamp can be checked to see if it is not yet valid
* for an SCT from a log for which a public key is configured, the server signature can be checked

If verification fails for at least one SCT and verification was not successful for at least one SCT, the connection is aborted.

Additionally, the server certificate chain and SCTs are stored for off-line verification (not yet working).  Off-line verification should be able to mark a log as untrusted.

As an optimization, on-line verification and storing of data from the server is only performed the first time a web server child process receives the data.  This saves some processing time as well as disk space.  For typical reverse proxy setups, very little processing overhead will be required.

Build
=====

Build it like this:

* Build OpenSSL 1.0.2-beta1
* Patch httpd trunk with src/proto1/httpd.patch (which has to be built using OpenSSL 1.0.2-beta1)
* If you want to store CT log configuration in a database, which will allow dynamic updates in the future, use a build of APR-Util with SQLite3 database support (--with-sqlite3) **and** use CTLogConfigDB instead of CTStaticLogConfig.
* Build certificate-transparency tools from https://code.google.com/p/certificate-transparency/
* Build mod\_ssl\_ct with apxs, adding -I/path/to/httpd/modules/ssl and -I/path/to/openssl/include
```
    apxs -ci -I/path/to/httpd/modules/ssl -I/path/to/openssl/include mod_ssl_ct.c ssl_ct_util.c ssl_ct_sct.c ssl_ct_log_config.c
```

Configuration
=============

Configure mod\_ssl\_ct like this:
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

### Support for concise logging of limited information

* proxy and server: log the SSL\_CT\_PEER\_STATUS envvar to see if peer is aware
* proxy: log the SSL\_PROXY\_SCT\_SOURCES envvar to see where SCTs came from

# Support for off-line auditing of SCTs received by the proxy from servers

A script to perform auditing (ctauditscts) is currently under development, but it isn't currently working.

Here's the related httpd processing:

* httpd processes queue the server certificate chain and SCTs in a file called audit\_\<PID\>.tmp in the CTAuditStorage directory.  These are flushed and renamed to audit\_\<PID\>.out when the child process exits (MaxConnectionsPerChild, load subsides, restart, stop).
* The individual files for audit, specific to one httpd child process, will not have duplicates (i.e., multiple occurrences of the exact same server certificate/chain and set of SCTs), though there can be duplicates among files for different httpd child processes.
* The off-line audit procedure should move the .out files elsewhere and audit the contents.  These .out files will grow unbounded for the life of the server if the set of unique server certificates + SCTs is unbounded.
* No provision is made for unbounded storage growth due to unbounded numbers of backend servers or unbounded numbers of child processes (each with its own .out file).
* The file contains a series of elements for each server: SERVER_START (0x0001), certificate data (leaf first followed by any intermediate certificates), and SCT data.
* Each certificate is represented by CERT_START (0x0002) and three-byte length followed by the certificate in DER.
* Each SCT is represented by SCT_START (0x0003) and two-byte length followed by the SCT.


