######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@verge.net.au
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999-2001  Horms
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

lib_LTLIBRARIES = libperditiondb_daemon_base.la

libperditiondb_daemon_base_la_SOURCES = packet.c packet.h \
	unix_socket.c unix_socket.h
libperditiondb_daemon_base_la_LDFLAGS    = -version-info 0:0:0
libperditiondb_daemon_base_la_LIBADD = @socket_lib@ -lvanessa_logger \
	-lvanessa_socket

INCLUDES = -I$(top_srcdir)/perdition
