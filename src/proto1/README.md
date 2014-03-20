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

TBD

Proxy processing overview
=========================

TBD
