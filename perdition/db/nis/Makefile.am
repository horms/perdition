######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@verge.net.au
#
# perdition
# Mail retrieval proxy server, NIS support
# Copyright (C) 1999-2005 Nathan Neulinge and Horms
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
######################################################################

EXTRA_DIST = README.perditiondb_nis

lib_LTLIBRARIES = libperditiondb_nis.la

libperditiondb_nis_la_SOURCES = \
perditiondb_nis.c \
perditiondb_nis.h

libperditiondb_nis_la_LDFLAGS    = -version-info 0:0:0

libperditiondb_nis_la_LIBADD     = @nsl_lib@ -lvanessa_logger

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition
