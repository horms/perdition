######################################################################
# Makefile.am                                               March 2000
# ChrisS                                              chriss@uk.uu.net
#
# perdition
# Mail retrieval proxy server, LDAP support
# Copyright (C) 1999-2002  ChrisS and Horms
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
# 02111-1307  USA
#
######################################################################

SUBDIRS = @ldap_doc_dir@

man_MANS = perditiondb_ldap_makedb.8

schema_sources = perdition.schema

EXTRA_DIST = perditiondb_ldap_makedb perditiondb_ldap_makedb.8 \
		$(schema_sources)

install-data-hook: $(schema_sources)
	if test -n "@ldap_schemadir@"; then \
		if test -n "$(DESTDIR)" -a \
				! -e "$(DESTDIR)@ldap_schemadir@"; then \
			$(top_srcdir)/mkinstalldirs \
				"$(DESTDIR)@ldap_schemadir@"; \
		fi; \
		if test -w "$(DESTDIR)@ldap_schemadir@"; then \
			install -m644 $< \
				"$(DESTDIR)@ldap_schemadir@/perdition.schema";\
		fi \
	fi


bin_SCRIPTS = perditiondb_ldap_makedb

lib_LTLIBRARIES = libperditiondb_ldap.la

libperditiondb_ldap_la_SOURCES = \
perditiondb_ldap.c \
perditiondb_ldap.h

libperditiondb_ldap_la_LDFLAGS    = -version-info 0:0:0

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
-I$(top_srcdir)/libjain \
@ssl_includes@ \
@ldap_includes@

libperditiondb_ldap_la_LIBADD = @ssl_lib@ @ldap_libs@
