######################################################################
# Makefile.am                                               March 2002
# Horms                                             horms@vergenet.net
#
# perdition
# Mail retrieval proxy server, ODBC support
# Copyright (C) 1999-2002 Horms and Frederic Delchambre
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

lib_LTLIBRARIES = libperditiondb_odbc.la

libperditiondb_odbc_la_SOURCES = \
perditiondb_odbc.c \
perditiondb_odbc.h

libperditiondb_odbc_la_LDFLAGS = -version-info 0:0:0

libperditiondb_odbc_la_LIBADD =  @ssl_lib@ @odbc_lib@ 

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
-I$(top_srcdir)/libjain \
@ssl_includes@
