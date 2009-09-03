######################################################################
# Makefile.am                                            November 2000
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
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#
######################################################################

EXTRA_DIST = perdition.conf Makefile.popmap.in Makefile.popmap popmap

perditionconfdir = $(sysconfdir)/perdition
perditionconf_DATA = perdition.conf popmap Makefile.popmap

install-data-hook:
	(cd $(DESTDIR)$(sysconfdir)/perdition/ && rm -f Makefile && \
		ln -sf Makefile.popmap Makefile)

uninstall-local:
	(cd $(DESTDIR)$(sysconfdir)/perdition/ && rm -f Makefile)
