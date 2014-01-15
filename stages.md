Development Stages for CT in httpd
==================================

# Prototype 1

## Level of functionality

* Web server can obtain SCTs from a statically configured set of logs.
* Web server will log whether or not client is CT-aware.
* Web server will return SCTs when client is CT-aware.
* Proxy will present itself as CT-aware to backend servers.
* Proxy will log information about SCTs (if any) from backend servers.
* Proxy will enqueue server certs/SCTs for audit.

## Implementation shortcuts

* Add any necessary hooks to mod_ssl to minimize collision with other active development, and implement new program logic in mod_ssl_ct.
* mod_ssl_ct will use certificate-transparency project **executable files** (if at all possible) to communicate with the log(s), avoiding what looks like a build nightmare.
