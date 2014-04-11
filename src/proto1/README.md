Log configuration overview
==========================

The following information can be configured for a log:

* public key
* URL
* audit status
* min and max valid timestamps
* general purpose "distrusted" flag

Partial information can be provided.  Any number of logs may be described.  A log may be identified by public key or by identifier, though the public key is needed for validation of the signature in an SCT received by the proxy.

This information can be configured statically in the httpd configuration, or configured in a SQLite3 database which is read by httpd at intervals.

The SQLite3 database is maintained by a command-line program (ctlogconfig).

## Configuration issues

* The public key is currently configured as the name of a file containing the PEM encoding of the key, so the PEM file has to exist with the same lifetime as the configuration in order to use that.  It may be more useful to store the DER encoding of the public key directly in the database, while allowing the administrator to specify a PEM or DER-formatted file to be read.
* ctlogconfig may allow the user to create multiple entries that describe the same log, such as when configuring a log URL without other information and then configuring a log URL for a particular log id.

## Use of log configuration by server mode

Server mode is concerned primarily with the URL of the log.  For each log URL found in the configuration (other than those marked as distrusted or with a trusted time interval in the past or the future), server certificates will be submitted to the log and the SCTs received will be sent to clients in the ServerHello once their timestamp is valid.

## Use of log configuration by proxy mode

Proxy mode uses the public key of the log in order to verify the signature of SCTs it receives.

Proxy mode checks the general purpose "distrusted" flag as well as interval of valid timestamps of a log to determine if an SCT is from a log known to be untrusted.

## Use of log configuration by off-line verification

A log URL can be specified for a particular log id so that verification of an SCT from that log uses the specified URL rather than the default coded in the certificate transparency tools.

SCT configuration
=================

The primary sources of SCTs sent to clients in server mode are

* received from logs for which a URL is configured
* included in a certificate extension
* included in the stapled OCSP response

In addition, the administrator can statically configure one or more SCTs for a particular server certificate.  This is configured by using the CTStaticSCTs directive to associate a directory maintained by the administrator with a server certificate; any files in that directory with extension .sct will also be sent when the certificate is used.

At run-time, a tree of directories contains SCTs fetched from logs as well as a SCT list built from fetched and configured SCTs.  The base of this directory tree is configured with the CTSCTStorage directive, and the certificate-specific directory name is the lower-case hex encoding of the SHA-256 hash of the DER form of the server leaf certificate.

Server processing overview
==========================

The server wants to send SCTs to the client.  SCTs in a certificate extension or stapled OCSP response will be sent without any special program logic.  The new processing handles sending SCTs configured by the administrator or received from known logs in the ServerHello.

The number of SCTs sent in the ServerHello (i.e., not including those in a certificate extension or stapled OCSP response) can be limited by the CTServerHelloSCTLimit direcive.

For each server certificate, a daemon process maintains an SCT list to be sent in the ServerHello, created from statically configured SCTs as well as those received from logs.  Logs marked as untrusted or with a maximum valid timestamp before the present time will be ignored.  Periodically the daemon will submit certificates to a log as necessary (due to changed log configuration or age) and rebuild the concatenation of SCTs.

The SCT list for a server certificate will be sent to any client that indicates awareness in the ClientHello when that particular server certificate is used.

Proxy processing overview
=========================

The proxy indicates CT awareness in the ClientHello by including the signed\_certificate\_timestamp extension.  It can recognize SCTs received in the ServerHello, in an extension in the server certificate, or in a stapled OCSP response.

On-line verification is attempted for each received SCT:

* for any SCT, the timestamp can be checked to see if it is not yet valid based on the current time as well as any configured valid time interval for the log
* for an SCT from a log for which a public key is configured, the server signature can be checked

If verification fails for at least one SCT and verification was not successful for at least one SCT, the connection is aborted.

Additionally, the server certificate chain and SCTs are stored for off-line verification.

As an optimization, on-line verification and storing of data from the server is only performed the first time a web server child process receives the data.  This saves some processing time as well as disk space.  For typical reverse proxy setups, very little processing overhead will be required.

## Support for off-line auditing of SCTs received by the proxy from servers

* httpd processes queue the server certificate chain and SCTs in a file called audit\_\<PID\>.tmp in the CTAuditStorage directory.  These are flushed and renamed to audit\_\<PID\>.out when the child process exits (MaxConnectionsPerChild, load subsides, restart, stop).
* The individual files for audit, specific to one httpd child process, will not have duplicates (i.e., multiple occurrences of the exact same server certificate/chain and set of SCTs), though there can be duplicates among files for different httpd child processes.
* The off-line audit procedure should move the .out files elsewhere and audit the contents.  These .out files will grow unbounded for the life of the server if the set of unique server certificates + SCTs is unbounded.
  * Currently a configuration mechanism to control the unbounded storage growth does not exist.
* The file contains a series of elements for each server: SERVER_START (0x0001), a key which is unique for this combination of leaf certificate and SCTs, certificate data (leaf first followed by any intermediate certificates), and SCT data.  SCTs provided in the ServerHello, certificate extension, or stapled OCSP response will be stored.
* The key is represented by KEY_START (0x0002) and two-byte length followed by the key.  While a particular audit file won't contain any duplicate data, duplicates are expected across the set of audit files, and the key can be used to quickly filter out duplicates.
  * The key is currently the SHA-256 digest of the leaf certificate and set of SCTs, in printable hex format.
* Each certificate is represented by CERT_START (0x0003) and three-byte length followed by the certificate in DER.
* Each SCT is represented by SCT_START (0x0004) and two-byte length followed by the SCT.

Prerequisites
=============

## Certificate transparency open source project

The certificate-transparency tools (https://code.google.com/p/certificate-transparency/source/browse/) are required for

* submission of server certificates to logs to obtain SCTs (which is also used simply to find the SCTs for certificates previously submitted
* off-line audit of SCTs received by proxy from backend servers

To avoid installing these tools on the web server machine (which is no fun!), you may

* Statically maintain SCTs for your server certificates using the log submission tool on another machine, and use the CTStaticSCTs directive to point to them
* Perform the off-line audit of SCTs received by proxy on another machine by moving the .out files from the CTAuditStorage directory to a machine with the tools installed.

### Certificate transparency tools on Windows

To my knowledge, no build is currently implemented for this.  In order to test log submission on Windows, you can modify the source file fakect.c to be able to copy an SCT to the right place on your system, and install the compiled form as ct.exe in the appropriate directory under CTToolsDir.

## OpenSSL 1.0.2

This is absolutely required for web server/proxy support.

## Python 2.x

2.7 is fine.  It has not been tested with 2.6 or earlier.  Python is required for manipulation of the log config database and for performing an off-line audit of SCTs received by proxy.  Neither of these has to be performed on the web server/proxy machine.

Build
=====

Build it like this:

* Build OpenSSL 1.0.2-beta1 or later
  * Windows: You need the head of the OpenSSL-1.0.2-stable branch to pick up later fixes.
* httpd trunk:
  * Patch httpd trunk (r1586719 or later) with src/proto1/httpd.patch, and build using OpenSSL 1.0.2-beta1 or later
* httpd 2.4.9:
  * T.B.D.
* If you want to store CT log configuration in a database, which will allow dynamic updates in the future, use a build of APR-Util with SQLite3 database support (--with-sqlite3) **and** use CTLogConfigDB instead of CTStaticLogConfig.
* Build certificate-transparency tools from https://code.google.com/p/certificate-transparency/
* Unix: Build mod\_ssl\_ct with apxs, adding -I/path/to/openssl/include
```
    apxs -ci -I/path/to/openssl/include mod_ssl_ct.c ssl_ct_util.c ssl_ct_sct.c ssl_ct_log_config.c
```
* Windows: Build mod\_ssl\_ct with cmake, installing to the same prefix as httpd and OpenSSL 1.0.2; here's an example:
```
    mkdir temp_build_dir
    cd temp_build_dir
    cmake -DCMAKE_INSTALL_PREFIX=same-as-others -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo \path\to\source
    nmake && nmake install
```

Configuration
=============

Configure mod\_ssl\_ct like this:
```
    LoadModule ssl_ct_module modules/mod_ssl_ct.so
    CTStaticLogConfig - - - - - http://localhost:8888/
    CTStaticLogConfig - - - - - http://otherhost:9999/
    CTStaticLogConfig - /path/to/log-public-key.pem - - - -
    CTAuditStorage /tmp/audit
    CTSCTStorage /tmp/newscts
    CTToolsDir /home/trawick/git/certificate-transparency
    CTMaxSCTAge 3600           (1 hour)
    CTServerHelloSCTLimit 100    (essentially unlimited)
    # CTStaticSCTs /path/to/server-cert.pem /path/to/directory
```
* If you want to statically define SCTs to return in addition to those from the log, put them individually in files with extension ".sct" in the directory for the server certificate specified by CTStaticSCTs.  A given directory can be used only for the specified certificate (one directory of static SCTs per server certificate).
* You can configure information about CT logs external to the httpd configuration by using the ctlogconfig program to create a database, and point to the database using the CTLogConfigDB directive.  This requires SQLite3 support in APR-Util.
* The statuscgi.py CGI script will display "peer-aware" or "peer-unaware" (and a few more standard SSL variables) based on whether or not mod\_ssl\_ct thinks the client understands CT.  (mod\_ssl+mod\_ssl\_ct+mod\_proxy and Chromium from the dev channel are both CT-aware clients.)

### Support for concise logging of limited information

* proxy and server: log the SSL\_CT\_PEER\_STATUS envvar to see if peer is aware
* proxy: log the SSL\_PROXY\_SCT\_SOURCES envvar to see where SCTs came from

# Performing off-line auditing 

* Apply the patch in file verify\_single\_proof.patch to the verify\_single\_proof.py script in the certificate-transparency tools.
* Set PYTHONPATH to find the necessary certificate-transparency libraries (probably just the src/python directory).  You may also have to add /usr/local/include if protobuf was installed to /usr/local.
* Set PATH to include the certificate-transparency/src/python/ct/client/tools directory.
* Run ctauditscts; the single required parameter is the value of the CTAuditStorage directive.
  * Provide a path to a log config db if the log URL for a given log id can be obtained.  (If not found, a default will be used.)

## Issues

* verify\_single\_proof.py is itself not complete; in particular, it does not report success/failure in an appropriate manner, so ctauditscts has no logic yet to detect success/failure.
* Logging of the results from verification is needed, along with a mechanism for reporting exceptions; this needs verify\_single\_proof to be completed.
