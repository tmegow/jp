bin_PROGRAMS = jp
if LINUX
SUBDIRS = pcre2
jp_SOURCES = jp.c json.c
AM_CFLAGS = -I${abs_builddir}/pcre2/src/
AM_LDFLAGS = -L${abs_builddir}/pcre2/ -lpcre2-8 -lm -no-install
endif
if OSX
SUBDIRS = pcre2 argp
jp_SOURCES = jp.c json.c
AM_CFLAGS = -Wno-switch -I${abs_builddir}/argp/ -I${abs_builddir}/pcre2/src/
AM_LDFLAGS = -L${abs_builddir}/argp/ -L${abs_builddir}/pcre2/ -largp -lpcre2-8 -lm -no-fast-install
endif
