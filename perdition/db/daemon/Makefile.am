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

noinst_LIBRARIES = libperditiondb_daemon_packet.a

libperditiondb_daemon_packet_a_SOURCES = packet.c packet.h

lib_LTLIBRARIES = libperditiondb_daemon.la

libperditiondb_daemon_la_SOURCES = \
perditiondb_daemon.c perditiondb_daemon.h unix_socket.c unix_socket.h
libperditiondb_daemon_la_LDFLAGS    = -version-info 0:0:0
libperditiondb_daemon_la_LIBADD = -ldb -L. -lperditiondb_daemon_packet

noinst_PROGRAMS = client server

client_SOURCES = client.c unix_socket.c unix_socket.h
client_LDADD = -lvanessa_logger -L. -lperditiondb_daemon_packet

server_SOURCES = server.c unix_socket.c unix_socket.h
server_LDADD = -lvanessa_logger -L. -lperditiondb_daemon_packet

INCLUDES=\
-I$(top_srcdir)/ \
-I$(top_srcdir)/perdition \
-I$(top_srcdir)/libjain \
-DPERDITIONDB_BDB_SYSCONFDIR=\"$(sysconfdir)/perdition\"

