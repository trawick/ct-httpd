INST = $(HOME)/inst/ct-64
# INST = $(HOME)/inst/ct24-64
APACHECTL = $(INST)/bin/apachectl
APXS = $(INST)/bin/apxs
OPENSSLINST = $(HOME)/inst/o102

DOTC = mod_ssl_ct.c ssl_ct_sct.c ssl_ct_util.c ssl_ct_log_config.c
DOTH = ssl_ct_sct.h ssl_ct_util.h ssl_ct_log_config.h
PY = *.py ctauditscts ctlogconfig
SOURCES = $(DOTC) $(DOTH) Makefile *.py

all: mod_ssl_ct.la

clean:
	rm -rf *.la *.lo *.o *.slo .libs

pep8:
	pep8 $(PY)

mod_ssl_ct.la: $(DOTC) $(DOTH)
	$(APXS) -c -I$(OPENSSLINST)/include $(DOTC)

install: mod_ssl_ct.la stop pure-install

pure-install: mod_ssl_ct.la
	$(APXS) -i mod_ssl_ct.la
	cp statuscgi.py $(INST)/cgi-bin
	cp ctlogconfig ctauditscts $(INST)/bin
	chmod 0755 $(INST)/cgi-bin/statuscgi.py

start:
	$(APACHECTL) -k start

stop:
	$(APACHECTL) -k stop

test:
	./testlogconfig.py
