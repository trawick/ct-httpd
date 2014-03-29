SETLOCAL
SET SSL_CT_CMAKE_OPTS=-DCMAKE_INSTALL_PREFIX=%HOME%\PREFIXES\251 -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo

SET BLDDIR=%HOME%\BUILDDIRS\ssl_ct
cd %HOME%
rd /s /q %BLDDIR%
mkdir %BLDDIR%
cd %BLDDIR%
cmake %SSL_CT_CMAKE_OPTS% %HOME%\git\ct-httpd\src\proto1
nmake
nmake install
