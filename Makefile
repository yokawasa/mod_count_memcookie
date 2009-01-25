##
##  Makefile -- Build procedure for sample count_memcookie Apache module
##

ap_basedir=/home/apache-2.2.2
builddir=.
top_srcdir=$(ap_basedir)
top_builddir=$(ap_basedir)
include $(ap_basedir)/build/special.mk

#   the used tools
APXS=$(ap_basedir)/bin/apxs
APACHECTL=$(ap_basedir)/bin/apachectl
MY_LDFLAGS=-L/usr/lib -lmemcache
MY_CFLAGS=-I/usr/include

#   the default target
all: mod_count_memcookie.o

mod_count_memcookie.o: mod_count_memcookie.c
	$(APXS) $(MY_LDFLAGS) $(MY_CFLAGS) -c mod_count_memcookie.c

#   install the shared object file into Apache
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_count_memcookie.o mod_count_memcookie.lo mod_count_memcookie.slo mod_count_memcookie.la

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

