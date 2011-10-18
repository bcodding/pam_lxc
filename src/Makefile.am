securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)
securelib_LTLIBRARIES = pam_lxc.la

#noinst_LTLIBRARIES = pam_lxc.la
#lib_LTLIBRARIES = libpam_lxc.la
#
#libpam_lxc_la_LIBADD = -lpam
#libpam_lxc_la_SOURCES = pam_lxc.c pam_lxc.h

pam_lxc_la_LDFLAGS = -no-undefined -avoid-version -module
pam_lxc_la_LIBADD = -lpam
pam_lxc_la_SOURCES = pam_lxc.c
