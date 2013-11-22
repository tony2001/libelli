AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libelli.la

libelli_la_SOURCES = elli.c keys.c verbum.c

libelli_la_LIBADD = @LTLIBOBJS@
libelli_la_LDFLAGS = -release @VERSION@

include_HEADERS = elli.h elli_version.h
EXTRA_DIST = elli.h elli_version.h
noinst_HEADERS = elli_config.h elli_internal.h
