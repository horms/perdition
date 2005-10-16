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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
# 02111-1307  USA
#
######################################################################

SUBDIRS = lib

lib_LTLIBRARIES = libperditiondb_daemon.la

COMMON_LIBRARY_ADD :=  @socket_lib@ -lvanessa_logger \
        -lvanessa_socket -L./lib -lperditiondb_daemon_base

libperditiondb_daemon_la_SOURCES = perditiondb_daemon.c perditiondb_daemon.h 
libperditiondb_daemon_la_LDFLAGS    = -version-info 0:0:0
libperditiondb_daemon_la_LIBADD = $(COMMON_LIBRARY_ADD)

noinst_PROGRAMS = client server

client_SOURCES = client.c 
client_LDADD = $(COMMON_LIBRARY_ADD)

server_SOURCES = server.c
server_LDADD = $(COMMON_LIBRARY_ADD)

INCLUDES = -I$(top_srcdir)/perdition -I$(top_srcdir)/libjain
