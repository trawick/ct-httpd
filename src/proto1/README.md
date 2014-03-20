Log configuration
=================

The following information can be configured for a log:

* public key
* URL
* audit status

Partial information can be provided.  Any number of logs may be described.

This information can be configured statically in the httpd configuration, or configured in a SQLite3 database which is read by httpd at intervals.

The SQLite3 database is maintained by a command-line program (ctlogconfig).

## Use of log configuration by server mode

Server mode is concerned primarily with the URL of the log.  For each log URL found in the configuration **without** being marked as having failed audit, server certificates will be submitted to the log and the SCTs received will be sent to clients (once their timestamp is valid).

## Use of log configuration by proxy mode

Proxy mode uses the public key in order to verify the signature of SCTs it receives.

Proxy mode checks the audit status of a log to determine if an SCT is from a log known to be untrusted.

