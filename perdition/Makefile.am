######################################################################
# Makefile.am                                            February 2000
# Horms                                             horms@vergenet.net
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999-2002  Horms
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
	(cd $(DESTDIR)$(sbindir) && ln -sf perdition perdition.pop3)
	(cd $(DESTDIR)$(mandir)/man8 && ln -sf perdition.8 perdition.pop3.8)
	(cd $(DESTDIR)$(sbindir) && ln -sf perdition perdition.pop3s)
	(cd $(DESTDIR)$(mandir)/man8 && ln -sf perdition.8 perdition.pop3s.8)
	(cd $(DESTDIR)$(sbindir) && ln -sf perdition perdition.imap4)
	(cd $(DESTDIR)$(mandir)/man8 && ln -sf perdition.8 perdition.imap4.8)
	(cd $(DESTDIR)$(sbindir) && ln -sf perdition perdition.imap4s)
	(cd $(DESTDIR)$(mandir)/man8 && ln -sf perdition.8 perdition.imap4s.8)


perdition_SOURCES = \
        config_file.c       config_file.h \
        getserver.c         getserver.h \
        greeting.c          greeting.h \
        imap4.c             imap4.h \
        imap4s.c            imap4s.h \
        imap4_in.c          imap4_in.h \
        imap4_out.c         imap4_out.h \
        imap4_write.c       imap4_write.h \
	int.h \
        io.c                io.h \
        io_select.c         io_select.h \
        log.h \
        options.c           options.h \
        pam.c               pam.h \
        perdition.c \
        perdition_types.h \
        pop3.c              pop3.h \
        pop3s.c             pop3s.h \
        pop3_in.c           pop3_in.h \
        pop3_out.c          pop3_out.h \
        pop3_write.c        pop3_write.h \
        protocol.c          protocol.h \
        protocol_t.h \
        queue_func.c        queue_func.h \
        quit.c              quit.h \
        setproctitle.c      setproctitle.h \
        token.c             token.h \
        server_port.c       server_port.h \
        str.c               str.h \
        ssl.c               ssl.h \
        username.c          username.h


INCLUDES= \
  -I$(top_srcdir)/libjain \
  -DPERDITION_LIBDIR=\"${libdir}\" \
  -DPERDITION_SYSCONFDIR=\"$(sysconfdir)/perdition\" \
  @ssl_includes@ 

# Removed because Debian doesn't like it
#LDFLAGS = -Wl,--rpath -Wl,@prefix@

LDADD = \
-L../libjain \
-L../libjain/.libs/ \
-ljain \
-lvanessa_adt \
-lvanessa_socket \
-lvanessa_logger \
-lpopt \
@pam_lib@ \
@socket_lib@ \
@nsl_lib@ \
@resolv_lib@ \
@dl_lib@ \
@ssl_lib@ \
@dmalloc_lib@

perdition_LDFLAGS = -rdynamic

