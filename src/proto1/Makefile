INST = $(HOME)/inst/ct-64
APACHECTL = $(INST)/bin/apachectl
APXS = $(INST)/bin/apxs
SSLSRC = $(HOME)/svn/httpd-ct/modules/ssl

SOURCES = mod_ssl_ct.c Makefile *.py

all: mod_ssl_ct.la

mod_ssl_ct.la: mod_ssl_ct.c
	$(APXS) -c -I$(SSLSRC) mod_ssl_ct.c

install: mod_ssl_ct.la stop pure-install

pure-install: mod_ssl_ct.la
	$(APXS) -i mod_ssl_ct.la

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
