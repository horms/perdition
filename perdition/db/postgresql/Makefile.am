######################################################################
# Makefile.am                                               April 2000
# Horms                                             horms@vergenet.net
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999  Horms
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

bin_SCRIPTS = perditiondb_postgresql_makedb

lib_LTLIBRARIES = libperditiondb_postgresql.la

libperditiondb_postgresql_la_SOURCES = \
perditiondb_postgresql.c \
perditiondb_postgresql.h

libperditiondb_postgresql_la_LDFLAGS    = -version-info 0:0:0

libperditiondb_postgresql_la_LIBADD = -lvanessa_adt -lpq -L@pg_libraries@

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
-I$(top_srcdir)/libjain \
-I@pg_includes@

