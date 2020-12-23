bin_PROGRAMS = jp
if LINUX
SUBDIRS = pcre2
jp_SOURCES = jp.c json.c
AM_CFLAGS = -I${abs_builddir}/pcre2/src/
AM_LDFLAGS = -L${abs_builddir}/pcre2/ -lpcre2-8 -lm -no-install
endif
