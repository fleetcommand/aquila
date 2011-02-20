
if USE_WINDOWS
WINDOWS_DEFS = -DUSE_WINDOWS
endif

DEFS = @DEFS@

bin_PROGRAMS = aqpasswd
aqpasswd_SOURCES = aqpasswd.c
aqpasswd_LDADD = -L../src/lib
aqpasswd_CFLAGS = $(WINDOWS_DEFS)


EXTRA_DIST = aqdtinstall.in verli_import ddch_import ynhub_import ptokax_import

noinst_SCRIPTS = aqdtinstall
CLEANFILES = aqdtinstall

aqdtinstall: aqdtinstall.in
	rm -rf $(@).tmp
	sed -e 's,@exec_prefix\@,$(prefix),g' ${@}.in > ${@}.tmp
	chmod +x ${@}.tmp
	mv ${@}.tmp $@
