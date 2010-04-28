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
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#
######################################################################

SUBDIRS = db

man_MANS = perdition.8 perditiondb.5

EXTRA_DIST = perdition.8 perditiondb.5

sbin_PROGRAMS = perdition
	          
install-exec-hook: install-man8
	for i in pop3 pop3s imap4 imap4s imaps; do \
		(cd $(DESTDIR)$(sbindir) && rm -f perdition.$$i && \
			ln -f perdition perdition.$$i); \
		(cd $(DESTDIR)$(mandir)/man8 && rm -f perdition.$$i && \
			ln -sf perdition.8 perdition.$$i.8); \
	done

uninstall-local:
	for i in pop3 pop3s imap4 imap4s imaps; do \
		rm -f $(DESTDIR)$(sbindir)/perdition.$$i; \
		rm -f $(DESTDIR)$(mandir)/man8/perdition.$$i.8; \
	done

perdition_SOURCES = \
        config_file.c       config_file.h \
        getserver.c         getserver.h \
        greeting.c          greeting.h \
        imap4.c             imap4.h \
        imap4s.c            imap4s.h \
        imap4_in.c          imap4_in.h \
        imap4_out.c         imap4_out.h \
        imap4_tag.c         imap4_tag.h \
        imap4_write.c       imap4_write.h \
	int.h \
        io.c                io.h \
        io_select.c         io_select.h \
        log.h \
	managesieve.c		managesieve.h \
	managesieve_in.c	managesieve_in.h \
	managesieve_out.c	managesieve_out.h \
	managesieve_write.c	managesieve_write.h \
        token.c             token.h \
        options.c           options.h \
        pam.c               pam.h \
        perdition.c \
	perdition_globals.h perdition_types.h \
        pop3.c              pop3.h \
        pop3s.c             pop3s.h \
        pop3_in.c           pop3_in.h \
        pop3_out.c          pop3_out.h \
	pop3_write.c        pop3_write.h \
        protocol.c          protocol.h \
        protocol_t.h \
        queue_func.c        queue_func.h \
        quit.c              quit.h \
        sock.h \
        setproctitle.c      setproctitle.h \
        server_port.c       server_port.h \
        str.c               str.h \
        ssl.c               ssl.h \
        username.c          username.h \
	unused.h


INCLUDES= \
-DPERDITION_LIBDIR=\"${libdir}\" \
-DPERDITION_SYSCONFDIR=\"$(sysconfdir)/perdition\" \
-DPERDITION_LOCALSTATEDIR=\"$(localstatedir)\" \
@ssl_includes@ 

# Removed because Debian doesn't like it
#LDFLAGS = -Wl,--rpath -Wl,@prefix@

LDADD = \
-lvanessa_adt \
-lvanessa_socket \
-lvanessa_logger \
-lpopt \
@pam_lib@ \
@socket_lib@ \
@dl_lib@ \
@ssl_lib@ \
@dmalloc_lib@

perdition_LDFLAGS = -rdynamic

