bin_PROGRAMS = jp
jp_SOURCES = jp.c json.c
if LINUX
SUBDIRS = pcre2
AM_CFLAGS = -I${abs_builddir}/pcre2/src/
AM_LDFLAGS = -L${abs_builddir}/pcre2/ -lpcre2-8 -lm -no-install
endif
if OSX
SUBDIRS = pcre2 argp
AM_CFLAGS = -Wswitch -I${abs_builddir}/argp/ -I${abs_builddir}/pcre2/src/
AM_LDFLAGS = -L${abs_builddir}/argp/ -largp -L${abs_builddir}/pcre2/ -lpcre2-8 -lm -no-install
endif
