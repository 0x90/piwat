# $Id: Makefile,v 1.6 2005/10/17 00:08:17 dugsong Exp $

PYTHON	= python
#CONFIG_ARGS = --with-pcap=$(HOME)/build/libpcap-0.8.3

# PYTHON = C:\\Python23\\python.exe
# CONFIG_ARGS = --with-pcap=..\\wpdpack

all: pcap.c
	$(PYTHON) setup.py config $(CONFIG_ARGS)
	$(PYTHON) setup.py build

pcap.c: pcap.pyx
	pyrexc pcap.pyx

install:
	$(PYTHON) setup.py install

test:
	$(PYTHON) test.py

pkg_win32:
	$(PYTHON) setup.py bdist_wininst

pkg_osx:
	bdist_mpkg --readme=README --license=LICENSE

clean:
	$(PYTHON) setup.py clean
	rm -rf build dist

cleandir distclean: clean
	$(PYTHON) setup.py clean -a
	rm -f config.h *~
