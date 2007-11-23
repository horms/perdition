######################################################################
# Makefile.am                                            February 2000
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

bin_PROGRAMS = makebdb

man_MANS = makebdb.1

EXTRA_DIST = makebdb.1

makebdb_SOURCES = \
        makebdb.c \
        options.c \
        options.h

makebdb_LDADD = -ldb -lpopt \
@dmalloc_lib@
