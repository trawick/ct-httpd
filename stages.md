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

### See the "Issues" section near the top of [src/proto1/mod_ssl_ct.c](https://github.com/trawick/ct-httpd/blob/master/src/proto1/mod_ssl_ct.c).
### See [src/proto1/README.md](https://github.com/trawick/ct-httpd/blob/master/src/proto1/README.md) for a more detailed description of processing, as well as information on building and configuring it.

