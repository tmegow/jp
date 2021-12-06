AC_PREREQ([2.71])
AC_INIT([jp],[1.0],[tmegow@gmail.com])
AC_CONFIG_SRCDIR([json.c])
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_HOST
build_linux=no
build_mac=no

# Detect the target system
case "${host_os}" in
    linux*)
        build_linux=yes
        ;;
    darwin*)
        build_mac=yes
        ;;
    *)
        AC_MSG_ERROR(["OS $host_os is not supported"])
        ;;
esac

AM_CONDITIONAL([LINUX], [test "$build_linux" = "yes"])
AM_CONDITIONAL([OSX], [test "$build_mac" = "yes"])
# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE
AC_PROG_MAKE_SET
AC_PROG_RANLIB
# Checks for libraries.
# Checks for header files.
CFLAGS=""

LT_PREREQ([2.2])
LT_INIT([static])
AC_CHECK_HEADERS([inttypes.h stdint.h stdlib.h string.h])
# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memmove memset pow])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_SUBDIRS([argp pcre2])
AC_OUTPUT
