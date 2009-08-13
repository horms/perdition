######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@verge.net.au
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999-2005  Horms <horms@verge.net.au>
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

if GDBM_BUILD
MAKEGDBM_DIR = makegdbm
endif
if BDB_BUILD
MAKEBDB_DIR = makebdb
endif

SUBDIRS = $(MAKEGDBM_DIR) $(MAKEBDB_DIR) \
	perdition debian etc packaging

EXTRA_DIST = \
README \
TODO \
INSTALL.in \
CODING_LOCATIONS.in\
CODING_LOCATIONS \
autogen.sh

clean-local:
	rm -f build-stamp
