######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@vergenet.net
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999  Horms
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

SUBDIRS = db

man_MANS = perdition.8 perditiondb.5

EXTRA_DIST = perdition.8 perditiondb.5

sbin_PROGRAMS = perdition
	          
install-exec-hook:
	(cd $(sbindir) && ln -sf perdition perdition.pop3)
	(cd $(sbindir) && ln -sf perdition perdition.imap4)


perdition_SOURCES = \
        config_file.c \
        config_file.h \
        daemon.c \
        daemon.h \
        getserver.c \
        getserver.h \
        greeting.c \
        greeting.h \
        options.c \
        options.h \
        pam.c \
	pam.h \
        perdition.c \
        perdition.h \
        perdition_types.h \
        pop3.c \
        pop3.h \
        pop3_in.c \
        pop3_in.h \
        pop3_out.c \
        pop3_out.h \
        pop3_write.c \
        pop3_write.h \
        protocol.c \
        protocol.h \
        protocol_t.h \
        quit.c \
        quit.h \
        imap4.c \
        imap4.h \
        imap4_in.c \
        imap4_in.h \
        imap4_out.c \
        imap4_out.h \
        imap4_write.c \
        imap4_write.h \
        token.c \
        token.h \
        queue_func.c \
        queue_func.h \
        server_port.c \
        server_port.h \
        str.c \
        str.h \
        log.h


INCLUDES= \
  -I$(top_srcdir)/libjain \
  -DPERDITION_LIBDIR=\"${libdir}\" \
  -DPERDITION_SYSCONFDIR=\"$(sysconfdir)/perdition\"

# Removed because Debian doesn't like it
#LDFLAGS = -Wl,--rpath -Wl,@prefix@

LDADD = \
-L../libjain \
-L../libjain/.libs/ \
-ljain \
-lvanessa_adt \
-lvanessa_socket \
-lpopt \
@pam_lib@ \
@socket_lib@ \
@nsl_lib@ \
@dl_lib@

perdition_LDFLAGS = -rdynamic

