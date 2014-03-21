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
* For off-line verification of SCTs and logs (using data received by the proxy), a log id is available from the SCT, and this should be correlated with the URL of the log in order to obtain a proof.
  * In order for off-line verification to use the same configuration, these two pieces of information are required.

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

In addition, the administrator can statically configure one or more SCTs for a particular server certificate.  This is configured by using the CTStaticSCTs directive to associate a directory maintained by the administrator with a server certificate; any files in that directory with extension .sct will also be sent when the certificate is used.

The base SCT directory is configured with the CTSCTStorage directive, and the certificate-specific directory name is the lower-case hex encoding of the SHA-256 hash of the DER form of the server leaf certificate.  This directory will contain SCTs received from configured logs.

The number of SCTs sent in the ServerHello (i.e., not including those in a certificate extension or stapled OCSP response) can be limited by the CTServerHelloSCTLimit direcive.

Server processing overview
==========================

Basically the server wants to send SCTs to the client.  SCTs in a certificate extension or stapled OCSP response will be sent without any special program logic.  The new processing handles sending SCTs configured by the administrator or received from known logs in the ServerHello.

For each server certificate, a daemon process maintains an SCT list to be sent in the ServerHello, created from statically configured SCTs as well as those received from logs.  Logs marked as untrusted will be ignored.  Periodically the daemon will submit certificates to a log as necessary (due to changed log configuration or age) and rebuild the concatenation of SCTs.

The SCT list for a server certificate will be sent to any client that indicates awareness in the ClientHello when that particular server certificate is used.

Proxy processing overview
=========================

The proxy indicates CT awareness in the ClientHello by including the signed\_certificate\_timestamp extension.  It can recognize SCTs received in the ServerHello, in an extension in the server certificate, or in a stapled OCSP response.

On-line verification is attempted for each received SCT:

* for any SCT, the timestamp can be checked to see if it is not yet valid
* for an SCT from a log for which a public key is configured, the server signature can be checked

If verification fails for at least one SCT and verification was not successful for at least one SCT, the connection is aborted.

Additionally, the server certificate chain and SCTs are stored for off-line verification (not yet working).  Off-line verification should be able to mark a log as untrusted.

As an optimization, on-line verification and storing of data from the server is only performed the first time a web server child process receives the data.  This saves some processing time as well as disk space.  For typical reverse proxy setups, very little processing overhead will be required.

## Support for off-line auditing of SCTs received by the proxy from servers

* httpd processes queue the server certificate chain and SCTs in a file called audit\_\<PID\>.tmp in the CTAuditStorage directory.  These are flushed and renamed to audit\_\<PID\>.out when the child process exits (MaxConnectionsPerChild, load subsides, restart, stop).
* The individual files for audit, specific to one httpd child process, will not have duplicates (i.e., multiple occurrences of the exact same server certificate/chain and set of SCTs), though there can be duplicates among files for different httpd child processes.
* The off-line audit procedure should move the .out files elsewhere and audit the contents.  These .out files will grow unbounded for the life of the server if the set of unique server certificates + SCTs is unbounded.
  * Currently a configuration mechanism to control the unbounded storage growth does not exist.
* The file contains a series of elements for each server: SERVER_START (0x0001), certificate data (leaf first followed by any intermediate certificates), and SCT data.
* Each certificate is represented by CERT_START (0x0002) and three-byte length followed by the certificate in DER.
* Each SCT is represented by SCT_START (0x0003) and two-byte length followed by the SCT.

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
    CTMaxSCTAge 3600           (1 hour)
    CTServerHelloSCTLimit 100    (essentially unlimited)
    # CTStaticSCTs /path/to/server-cert.pem /path/to/directory
```
* If you want to statically define SCTs to return in addition to those from the log, put them individually in files with extension ".sct" in the directory for the server certificate specified by CTStaticSCTs.
* You can configure information about CT logs external to the httpd configuration by using the ctlogconfig program to create a database, and point to the database using the CTLogConfigDB directive.  This requires SQLite3 support in APR-Util.
* The statuscgi.py CGI script will display "peer-aware" or "peer-unaware" (and a few more standard SSL variables) based on whether or not mod\_ssl\_ct thinks the client understands CT.  (mod\_ssl+mod\_ssl\_ct+mod\_proxy and Chromium from the dev channel are both CT-aware clients.)

### Support for concise logging of limited information

* proxy and server: log the SSL\_CT\_PEER\_STATUS envvar to see if peer is aware
* proxy: log the SSL\_PROXY\_SCT\_SOURCES envvar to see where SCTs came from

# Performing off-line auditing 

* Apply this patch to the verify\_single\_proof script in the certificate-transparency tools:
```
--- a/src/python/ct/client/tools/verify_single_proof.py
+++ b/src/python/ct/client/tools/verify_single_proof.py
@@ -40,7 +40,11 @@ def run():
 
     #TODO(eranm): Attempt fetching the SCT for this chain if none was given.
     cert_sct = ct_pb2.SignedCertificateTimestamp()
-    cert_sct.ParseFromString(open(FLAGS.sct, 'rb').read())
+    #cert_sct.ParseFromString(open(FLAGS.sct, 'rb').read())
+    raw_sct = open(FLAGS.sct, 'rb').read()
+    cert_sct.version = 0
+    cert_sct.timestamp = struct.unpack_from('>Q', raw_sct, 2 + 33)[0]
+
     print 'SCT for cert:', cert_sct
 
     constructed_leaf = create_leaf(cert_sct.timestamp,
```
* Set PYTHONPATH to find the necessary certificate-transparency libraries (probably just the src/python directory).  You may also have to add /usr/local/include if protobuf was installed to /usr/local.
* Set PATH to include the certificate-transparency/src/python/ct/client/tools directory.
* Run ctauditscts; the single required parameter is the value of the CTAuditStorage directive.

## Issues

* Performing the off-line audit on the web server machine requires various prerequisites due to the reliance on certificate-transparency tools.  It may be appropriate to run a script on the web server machine to move the files elsewhere where installing extra dependencies is not as big a concern.  (The same is true of the log submission mechanism.)
* ctauditscts has no provision for passing verify\_single\_proof.py the server name and port of the log.  Verification is dependent on the suitability of the default log coded in verify\_single\_proof.py (currently ct.googleapis.com/pilot).
* Some resolution is needed for the required patch to verify\_single\_proof.py once more important issues are resolved.
* verify\_single\_proof.py is itself not complete, but that is planned.
* Logging of the results from verification is needed, along with a mechanism for reporting exceptions.