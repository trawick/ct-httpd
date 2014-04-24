ct-httpd
========

This is a project to implement Certificate Transparency in
Apache httpd.

httpd trunk as of r1589154 contains a new module, mod\_ssl\_ct,
and new commands, ctlogconfig and ctauditscts, for deploying
Certificate Transparency in an httpd server or proxy.

* http://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html
* http://httpd.apache.org/docs/trunk/programs/ctlogconfig.html

These features were originally maintained in this repository,
in the src/proto1 subdirectory.

Further development will take place in ASF svn.

A backport of the feature to the stable httpd 2.4.x branch
is available here:

* https://github.com/trawick/ct-httpd/blob/master/src/2.4.x/

Documentation here
==================

* Original docs for mod\_ssl\_ct and related commands:
  https://github.com/trawick/ct-httpd/blob/master/src/proto1/README.md
* Generic description of possible web server or proxy implementation:
  https://github.com/trawick/ct-httpd/blob/master/GenericServerAndProxy.md
* Building mod\_ssl\_ct with the stable httpd 2.4.x branch:
  https://github.com/trawick/ct-httpd/blob/master/src/2.4.x/README.md
