######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@verge.net.au
# Verge Systems International                     http://vergenet.net/
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
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#
######################################################################

if CDB_BUILD
CDB_DIR = cdb
endif
if GDBM_BUILD
GDBM_DIR = gdbm
endif
if BDB_BUILD
BDB_DIR = bdb
endif
if LDAP_BUILD
LDAP_DIR = ldap
endif
if MYSQL_BUILD
MYSQL_DIR = mysql
endif
if ODBC_BUILD
ODBC_DIR = odbc
endif
if POSIX_REGEX_BUILD
POSIX_REGEX_DIR = posix_regex
endif
if NIS_BUILD
NIS_DIR = nis
endif
if PG_BUILD
PG_DIR = postgresql
endif
if DEAMON_MAP_BUILD
DEAMON_MAP_DIR = daemon
endif

SUBDIRS = \
  $(CDB_DIR) \
  $(GDBM_DIR) \
  $(BDB_DIR) \
  $(LDAP_DIR) \
  $(MYSQL_DIR) \
  $(ODBC_DIR) \
  $(NIS_DIR) \
  $(PG_DIR) \
  $(POSIX_REGEX_DIR) \
  $(DEAMON_MAP_DIR)
