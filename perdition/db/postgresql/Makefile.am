######################################################################
# Makefile.am                                               April 2000
# Horms                                             horms@verge.net.au
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999-2005  Horms
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

man_MANS = perditiondb_postgresql_makedb.8

EXTRA_DIST = perditiondb_postgresql_makedb perditiondb_postgresql_makedb.8

sbin_SCRIPTS = perditiondb_postgresql_makedb

lib_LTLIBRARIES = libperditiondb_postgresql.la

libperditiondb_postgresql_la_SOURCES = \
perditiondb_postgresql.c \
perditiondb_postgresql.h

libperditiondb_postgresql_la_LDFLAGS    = -version-info 0:0:0

PG_LIBPATH	:= $(shell pg_config --libdir)
PG_INCLUDEPATH	:= $(shell pg_config --includedir)

libperditiondb_postgresql_la_LIBADD	= @ssl_lib@ \
@socket_lib@ @nsl_lib@ @crypt_lib@ -lvanessa_logger -lvanessa_adt \
-L$(PG_LIBPATH) -lpq

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
@ssl_includes@ \
-I$(PG_INCLUDEPATH)
