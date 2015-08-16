mod\_ssl\_ct with httpd 2.4.x
=============================

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

The patch has been tested with the 2.4.16 release tarballs and may work with later 2.4.x releases as well.  For prior releases, check the git history for earlier versions of the patch.

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
