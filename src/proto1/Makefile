INST = $(HOME)/inst/ct-64
APACHECTL = $(INST)/bin/apachectl
APXS = $(INST)/bin/apxs
SSLSRC = $(HOME)/svn/httpd-ct/modules/ssl
OPENSSLINST = $(HOME)/inst/o102

SOURCES = mod_ssl_ct.c ssl_ct_sct.h ssl_ct_sct.c ssl_ct_util.h ssl_ct_util.c Makefile *.py

all: mod_ssl_ct.la

clean:
	rm -rf *.la *.lo *.o *.slo .libs

mod_ssl_ct.la: mod_ssl_ct.c ssl_ct_sct.h ssl_ct_sct.c ssl_ct_util.c ssl_ct_util.h
	$(APXS) -c -I$(SSLSRC) -I$(OPENSSLINST)/include mod_ssl_ct.c ssl_ct_sct.c ssl_ct_util.c

install: mod_ssl_ct.la stop pure-install

pure-install: mod_ssl_ct.la
	$(APXS) -i mod_ssl_ct.la
	cp statuscgi.py $(INST)/cgi-bin
	cp ctlogconfig $(INST)/bin
	chmod 0755 $(INST)/cgi-bin/statuscgi.py

TS := $(shell date)
LINES := $(shell cat $(SOURCES) | grep -v '^$$' | wc -l)

start:
	$(APACHECTL) -k start

stop:
	$(APACHECTL) -k stop

test: install
	python testdotconf.py

config:
	python conf.py ssl_ct $(INST)
	$(APACHECTL) -t
	$(APACHECTL) -M | grep ssl_ct

metrics:
	@echo $(TS) $(LINES) >> metrics.txt
	cat metrics.txt
