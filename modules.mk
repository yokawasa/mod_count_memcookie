mod_count_memcookie.la: mod_count_memcookie.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_count_memcookie.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_count_memcookie.la
