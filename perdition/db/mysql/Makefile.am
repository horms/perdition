######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@verge.net.au
#
# perdition
# Mail retrieval proxy server, MySQL support
# Copyright (C) 1999-2004 Horms and Frederic Delchambre
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

man_MANS = perditiondb_mysql_makedb.8

EXTRA_DIST = perditiondb_mysql_makedb perditiondb_mysql_makedb.8

sbin_SCRIPTS = perditiondb_mysql_makedb

lib_LTLIBRARIES = libperditiondb_mysql.la

libperditiondb_mysql_la_SOURCES = \
perditiondb_mysql.c \
perditiondb_mysql.h

libperditiondb_mysql_la_LDFLAGS = -version-info 0:0:0

libperditiondb_mysql_la_LIBADD =  @ssl_lib@ @mysql_libs@

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
-I$(top_srcdir)/libjain \
@ssl_includes@ \
@mysql_includes@
