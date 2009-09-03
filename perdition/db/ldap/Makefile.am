######################################################################
# Makefile.am                                               March 2000
# ChrisS                                              chriss@uk.uu.net
#
# perdition
# Mail retrieval proxy server, LDAP support
# Copyright (C) 1999-2005  ChrisS and Horms
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#
######################################################################

if LDAP_DOC_BUILD
LDAP_DOC_DIR = doc
endif

SUBDIRS = $(LDAP_DOC_DIR)

man_MANS = perditiondb_ldap_makedb.8

schema_sources = perdition.schema

EXTRA_DIST = perditiondb_ldap_makedb perditiondb_ldap_makedb.8 \
		$(schema_sources)

if LDAP_SCHEMA
install-data-hook: $(schema_sources)
	test -n "@ldap_schemadir@"
	mkdir -p "$(DESTDIR)@ldap_schemadir@"
	chmod 755 "$(DESTDIR)@ldap_schemadir@"
	install -m 644 $< "$(DESTDIR)@ldap_schemadir@/"
endif

sbin_SCRIPTS = perditiondb_ldap_makedb

lib_LTLIBRARIES = libperditiondb_ldap.la

libperditiondb_ldap_la_SOURCES = \
perditiondb_ldap.c \
perditiondb_ldap.h

libperditiondb_ldap_la_LDFLAGS    = -version-info 0:0:0

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
@ldap_includes@

libperditiondb_ldap_la_LIBADD = @ldap_libs@ -lvanessa_logger
