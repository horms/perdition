######################################################################
# Makefile.am                                               March 2002
# Horms                                             horms@verge.net.au
#
# perdition
# Mail retrieval proxy server, ODBC support
# Copyright (C) 1999-2005 Horms and Frederic Delchambre
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

man_MANS = perditiondb_odbc_makedb.8

EXTRA_DIST = perditiondb_odbc_makedb perditiondb_odbc_makedb.8

sbin_SCRIPTS = perditiondb_odbc_makedb

lib_LTLIBRARIES = libperditiondb_odbc.la

libperditiondb_odbc_la_SOURCES = \
perditiondb_odbc.c \
perditiondb_odbc.h

libperditiondb_odbc_la_LDFLAGS = -version-info 0:0:0

libperditiondb_odbc_la_LIBADD =  @ssl_lib@ @odbc_libs@ 

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
@ssl_includes@
