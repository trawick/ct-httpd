ct-httpd
========

Certificate Transparency in httpd

This describes possible implementations of Certificate Transparency in web and/or proxy servers.  Different levels of compliance with Certificate Transparency are described in terms of configurable modes of operation. 

“Web server” in this document serves the role of “TLS server” while “proxy server” in this document serves the role as “TLS client.” 

Several "SSL variables" are referred to in the description.  Such variables are useful as information for web applications, for custom logging, and in some cases specific server processing can be triggered by specific values.  (These variables are often referred to as [environment variables](http://httpd.apache.org/docs/2.4/mod/mod_ssl.html#envvars), though in the case of mod_ssl they constitute a more general API.)

# Log submission

Obtaining an SCT from a log is of course crucial for CT.  Mechanisms exist for the CA to handle this (inclusion of SCT in a certificate extension or OCSP stapling response) but obtaining an SCT is also a normal, server-based activity (*if* the CA didn't handle it, *when* it is appropriate to submit the server certificate to additional logs).

Two models are described here -- a completely manual process handled by the server administrator, and an automated process implemented in the server software.  Either model can be used to ensure that the server sends SCTs from a set of logs which are trusted by clients, even after the occasional audit failure or decommissioning of a particular log.

## Manual log submission

The web/proxy server administrator uses a log submission application to submit a server certificate to a log and obtain an SCT in a suitable format.  This tool can maintain a set of SCTs in a suitable format as certificates are submitted to multiple logs.  Discovery of the failure of a log and potentially using an additional log requires manual intervention.

## Automated log submission

The server configuration includes a reference to a service (e.g., URL) which maintains a list of trusted logs.  (The details of this service are *TBD*.)  The server periodically checks the list of trusted logs, obtains SCTs as necessary from a configurable number of those logs, and includes them in the TLS extension when handshaking with *aware* clients.

The automation avoids the need to configure those details in every server and allows dynamic updates when a trusted log fails.

# Web server processing

Supporting TLS communication from a client to a server (possibly upgraded after initial, unencrypted communication); the OCSP Stapling feature referred to below may be missing from some web server implementations or purposefully disabled 

## Web server is configured in “SCT-required” mode 

* The processing described is for clients which request an SCT.  A client which is able to handle an SCT in **any** form **must** handle all forms, so a client that does not include the CertificateStatus extension is an *unaware* client.
* The administrator will use the appropriate log submission mechanism (described above).
  * This is absolutely required if the SCT is not in a certificate extension and the SCT is not returned by the OCSP server. 
  * This should be used to add responses from one or more additional logs that a client may require. 
* The server software will ensure that at least one SCT is available in the certificate extension, or the SCT TLS extension is available separately via the log submission mechanism, or the SCT is part of the OCSP stapling response. 
  * Processing should fail at the earliest point practical if this requirement is not met, which may be at the time of server startup or during the handshake. 
    * The server can check for the extension in the certificate or the TLS extension in foo.pem at startup. 
    * The earliest (practical) point that the OCSP stapling response may be examined will vary according to the server implementation. 
    * Does the SCT-available status need to be stored in the session cache?  No, validation will occur on the initial handshake. 
* The server will perform basic sanity checking on all SCTs at the earliest point practical if a check fails, since the administrator can diagnose a configuration problem much more easily when the server software identifies the issue. 
* The server will represent the source(s) of SCT in SSL variable SSL_SCT_SOURCES; this will be a comma-delimited list of source types, with these types represented by “certext” (certificate extension), “tlsextfile” (TLS extension in ServerInfoFile), and “ocsp” (part of OCSP stapling response).
 * In the event that the client is *unaware*, SSL_SCT_SOURCES will be set to "none".

## Web server is configured in “opportunistic SCT” mode 

* The processing described is for clients which request an SCT.  A client which is able to handle an SCT in **any** form **must** handle all forms, so a client that does not include the CertificateStatus extension is an *unaware* client.
* The possible lack of one or more SCTs to provide to the client will not result in failures triggered by the server (though the client may refuse interoperation). 
* If an SCT is available, the server will perform basic sanity checking on it and fail at the earliest point practical if a check fails. 
* If an SCT is available, the server will represent the source(s) of SCT in SSL variable SSL_SCT_SOURCES as described previously.  Otherwise it will be set to “none”. 
 * In the event that the client is *unaware*, SSL_SCT_SOURCES will be set to "none".

## Web server is configured in SCT-unaware mode 

* This non-default mode might be required to temporarily work around known configuration or software implementation problems. 
* There is no requirement that an SCT will be delivered, but it is not specifically prevented. 
* Any of the three mechanisms (certificate extension, TLS extension provided by the administrator as part of the server configuration, part of OCSP stapling response) can be used, but no sanity checks will be performed and SSL_SCT_SOURCES will be set to “unknown” or unset. 

# Proxy processing

Typical scenarios include 

* proxy initiates TLS connection to statically configured back-end servers, often under the same administrative and network control as the proxy (i.e., often “trusted”) 
* proxy initiates TLS connection to arbitrary back-end servers (i.e., “untrusted”) 
* CONNECT over TLS to untrusted back-end servers (i.e., client has TLS  connection to server and issues CONNECT request to connect to backend) 
* forward proxy over SSL to untrusted back-end servers (BIG-IP has this particular feature) 

The proxy is a TLS client in these scenarios, initiating the handshake with a back-end server.  Depending on the configuration, it must decide what action to take if no SCT is received during the handshake or if it is obviously invalid, or if the log which generated the SCT is known to be untrusted. 

In the case of multiple SCTs provide in a handshake, a single valid SCT is sufficient, in order to bypass additional processing.  (This is an obvious area for variation; some failures to accept a particular SCT may not be unusual, including receiving SCTs from logs which are unknown to the proxy or which are known to have failed audit.) 

An SCT cannot be validated unless the public key of the log which generated it is available; thus, logs are expected to be statically configured to the proxy, possibly in a manner that can be updated dynamically when a log fails an audit. 

From Ben Laurie:
>Right - I think relying on server operators to keep configuration in 
>line with reality is a bad idea - instead they should use some 
>mechanism TBD to get the current list (note that this mechanism, 
>unlike the one for servers, needs some kind of transparency of its 
>own). 

When an SCT is provided during the handshake, the proxy can determine if the SCT provided is associated with the server certificate if the log which generated the SCT is trusted. 

The CertificateStatus extension should always be included in the ClientHello when SCT processing is enabled; it may of course be enabled for other reasons. 

Log auditing is an asynchronous operation, so the server certificate and SCT(s) must be stored for use by auditing. As the same backend servers will likely be accessed frequently by the proxy, it may be necessary for the proxy to avoid storing duplicated information indiscriminately to control resource consumption though the auditing mechanism should handle duplications appropriately.

SCT processing for trusted back-end servers (typical for reverse proxy) should be easy to disable, even in “SCT-required” mode.  Presumably if certificate validation is explicitly disabled for a back-end server then SCT processing would not be desired either. 

## Log auditing application

* A web proxy when communicating with untrusted TLS servers will queue data for auditing, to be processed off-line by the log auditing application.  The auditing application should expect to see duplicate input.
* Log auditing failures should be reflected in the set of logs known to the proxy server, though that may require manual intervention by the administrator. 

## Proxy is configured in “SCT-required” mode 

The handshake will be aborted if an SCT is not provided by the server or if immediate validation fails for all received SCTs. 

SSL_PROXY_SCT_SOURCES – this will be a comma-delimited list of source types, with these types represented by “certext” (SCT is in certificate extension), “tlsext” (SCT is in TLS extension), and “ocsp” (SCT is in OCSP stapling response). 

SSL_PROXY_SCT_STATUS – “valid” or “invalid” or “unknown-log” 

## Proxy is configured in “opportunistic SCT” mode 

In “opportunistic SCT” mode, the lack of an SCT from a back-end server is not considered an error; however, if one is available then it will be processed in the same manner as in “SCT-required” mode. 

SSL_PROXY_SCT_SOURCES – same as above, or “none” if no SCT is available 

SSL_PROXY_SCT_STATUS – same as above, or “none” if no SCT is available 

## Proxy is configured in “SCT-unaware” mode 

All SCT processing by the proxy is omitted. 

SSL_PROXY_SCT_SOURCES – “unknown” or unset

SSL_PROXY_SCT_STATUS – “unknown” or unset 

# Miscellaneous notes

* The only manner in which a client will receive an SCT from an OCSP responder is via OCSP stapling; separate request flows are not needed for Certificate Transparency.
