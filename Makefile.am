all-local:    module

module: mod_authn_linotp.c
		if test "$(srcdir)" != "."; then $(CP) $(srcdir)/mod_authn_linotp.c .; fi
		$(APXS) -c -D_REENTRANT `echo $(GCC_WARN_FLAGS) | sed -r 's/ -/ -Wc,-/g'` -l crypto -l curl mod_authn_linotp.c

install-exec-local: module
		$(APXS) -S LIBEXECDIR="$(DESTDIR)`$(APXS) -q LIBEXECDIR`" -i mod_authn_linotp.la
		
install-data-local:
		install authn_linotp.load $(DESTDIR)`$(APXS) -q SYSCONFDIR`/mods-available/

install-exec-hook:
		test -z "$(STRIP)" || $(STRIP) $(DESTDIR)`$(APXS) -q LIBEXECDIR`/mod_authn_linotp.so

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST=         ChangeLog LICENSE mod_authn_linotp.c authn_linotp.load

