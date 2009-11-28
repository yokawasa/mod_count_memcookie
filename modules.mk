MOD_COUNT_MEMCOOKIE = mod_count_memcookie memcached_funcs\

HEADER = memcached_funcs.h \

${MOD_COUNT_MEMCOOKIE:=.slo}: ${HEADER}
${MOD_COUNT_MEMCOOKIE:=.lo}: ${HEADER}
${MOD_COUNT_MEMCOOKIE:=.o}: ${HEADER}

mod_count_memcookie.la: ${MOD_COUNT_MEMCOOKIE:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_COUNT_MEMCOOKIE:=.lo}

DISTCLEAN_TARGETS = modules.mk

shared =  mod_count_memcookie.la
