######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@vergenet.net
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999-2001  Horms <horms@vergenet.net>
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

LATEX = latex
DVIPS = dvips
PS2PDF = ps2pdf
GUNZIP = gunzip


gzeps_sources = ds5dump.eps.gz mail-ldapdump.eps.gz

tex_sources = perdition_ldap.tex

EXTRA_DIST = perdition_ldap.lyx $(gzeps_sources) $(tex_sources)

all-local: perdition_ldap.pdf

clean-local:
	rm -f *.aux *.log *.pdf *.dvi *.ps *.eps

dvi-local: perdition_ldap.dvi

perdition_ldap.dvi: $(tex_sources) $(gzeps_sources:.eps.gz=.eps)
	$(LATEX) $<

%.ps: %.dvi
	$(DVIPS) $< -o $@

%.pdf: %.ps
	$(PS2PDF) $< $@

%.eps: %.eps.gz
	$(GUNZIP) -c $< > $@
