
PACKAGE = @PACKAGE@
VERSION = @VERSION@

EXTRA_DIST = config.rpath TODO ChangeLog LICENSE AUTHORS COPYING INSTALL README.windows README.getaddrinfo README doc/aquila-manual.txt config.h.in depcomp install-sh missing ABOUT-NLS contrib/aquila.png contrib/aquila.ico
SUBDIRS = po src tools

ACLOCAL_AMFLAGS = -I m4

CURRENTURL = $(shell svn info | grep URL | cut -c 6-)

commit: 
	make -C src indent
if ENABLE_NLS
	make -C po update-po
endif
	svn commit

log:
	@svn diff ChangeLog 2>&1 | grep -e "^+" | grep -v -e "^++" | cut -c 2- | sed -r 's/^[\t ]*//'

commitlog:
	make -C src indent
if ENABLE_NLS
	make -C po update-po
endif
	@svn diff ChangeLog 2>&1 | grep -e "^+" | grep -v -e "^++" | cut -c 2- | sed -r 's/^[\t ]*//' > CommitMessage
	echo "Commit Message:"
	@cat CommitMessage
	svn commit -F CommitMessage
	@echo
	@rm -f CommitMessage

release: commit dist
	svn copy  ${CURRENTURL} svn://gw/aquila/tags/aquila-${VERSION} -m "Aquila Release ${VERSION}"
	@echo Release ${VERSION}
	@echo File: aquila-${VERSION}.tar.gz

dtinstall: install
	tools/aqdtinstall

aquila-${VERSION}-win32.tgz: src/aquila.exe tools/aqpasswd.exe
	mkdir -p windist
	cp README LICENSE Changelog windist
	cp src/aquila.exe windist
	cp tools/aqpasswd.exe windist
	tar -C windist -zcvf aquila-${VERSION}-win32.tgz .

windist: aquila-${VERSION}-win32.tgz
