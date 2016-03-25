mod\_ssl\_ct with some httpd 2.4
================================

You'll use an svn checkout of httpd trunk to get mod\_ssl\_ct, and compile and install that module using ``apxs`` from
your httpd 2.4 install.  Depending on the level of httpd 2.4, it may need to be patched first.  See the following 
sections for more details.

mod\_ssl\_ct with httpd 2.4.20 and higher
=========================================

No patches to httpd 2.4 are required starting with 2.4.20.  However, environment variables ``SSL_CT_PROXY_STATUS`` and
``SSL_CT_PROXY_SCT_SOURCES`` won't be set.  (The proxy API added in trunk requires too many changes to backport; a simpler
model is needed for filling in those environment variables.  The issue is having the backend connection and the frontend
``request_rec`` available at the same time, at a point that a hook can be called.)

mod\_ssl\_ct with httpd 2.4.18 and 2.4.17
=========================================

When checking out httpd trunk to get mod\_ssl\_ct, get revision 1735948 if you want ``SSL_CT_PROXY_STATUS`` and
``SSL_CT_PROXY_SCT_SOURCES`` to be set.  As of later revisions, mod\_ssl\_ct in trunk is ready to be compiled with
httpd 2.4.20 or later.

## New APIs in mod_ssl and mod_proxy

The svn revisions needed are:

* r1586719 - add the mod_proxy API
* r1587607 - add the mod_ssl APIs, change cmake-based build for Windows to export new hooks
* r1588868 - fix a warning in new mod_ssl APIs with some unknown level of gcc
* r1589699 - export mod\_ssl APIs when using traditional Windows build mechanism
* r1645529 - improve error handling when rejecting proxy backend connection due to "CTProxyAwareness require" (not a critical fix)
* r1661487 (mod_ssl.c, mod_ssl_openssl.h) - add proxy indicator to ssl pre_connection hook

These revisions are bundled in the following patch, which you can apply to a checkout of the httpd 2.4.x branch to add the APIs:

* https://github.com/trawick/ct-httpd/blob/master/src/2.4.x/httpd-2.4.x.patch

The patch has been tested with the httpd 2.4.17 code (not yet released at the time of this writing) and may work with later 2.4.x releases as well.  For prior httpd releases, including 2.4.16, check the git history for earlier versions of the patch.

Build httpd as you normally would, ensuring that you have OpenSSL 1.0.2-beta3 or later so that mod\_ssl\_ct (which requires OpenSSL 1.0.2) and httpd and the rest of the modules are using the same level of OpenSSL.

For example:
```
./configure --prefix=$HOME/2.4-ct --enable-ssl --with-ssl=/path/to/102 --other-options
```

## The module itself

Just check out httpd trunk to get the code; you'll be able to easily keep up to date with later fixes applied to mod\_ssl\_ct in trunk.

```
$ svn co https://svn.apache.org/repos/asf/httpd/httpd/trunk httpd-trunk
```

### Building the module on Unix

Change to the modules/ssl directory of your httpd trunk checkout, then use the apxs in your install of the patched httpd 2.4.x, as follows:
```
$ /path/to/2.4.x/bin/apxs -ci -I/path/to/openssl/include mod_ssl_ct.c ssl_ct_util.c ssl_ct_sct.c ssl_ct_log_config.c
```

### Building the module on Windows

Send me an e-mail if you actually need to do this.

(in short, do something fairly obvious with the CMakeLists.txt file in the src/proto1 subdir of this repo -- https://github.com/trawick/ct-httpd/blob/master/src/proto1/CMakeLists.txt)

## Command-line programs

See ctauditscts and ctlogconfig in the support subdirectory of your httpd trunk checkout.  They're Python, so they don't need to be compiled.

## Documentation

Just use the httpd trunk documentation:

* http://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html
* http://httpd.apache.org/docs/trunk/programs/ctlogconfig.html
