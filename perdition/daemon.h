/**********************************************************************
 * daemon.h                                              September 1999
 * Horms                                             horms@vergenet.net
 *
 * Close and fork to become a daemon.
 *
 * Notes from unix programmer faq
 * http://www.landfield.com/faqs/unix-faq/programmer/faq/
 *
 * Almost none of this is necessary (or advisable) if your daemon is being
 * started by `inetd'.  In that case, stdin, stdout and stderr are all set up
 * for you to refer to the network connection, and the `fork()'s and session
 * manipulation should *not* be done (to avoid confusing `inetd').  Only the
 * `chdir()' and `umask()' steps remain as useful.
 *
 * perdition
 * Mail retreival proxy server
 * Copyright (C) 1999  Horms
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifndef DAEMON_FRUB
#define DAEMON_FRUB

#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>

#include "log.h"
#include "str.h"


void daemon_process(void);
void daemon_inetd_process(void);
void daemon_become_child(void);
void daemon_close_fd(void);
int daemon_setid(const char *user, const char *group);
void daemon_exit_cleanly(int i);
void daemon_noop_handler(int sig);


#endif
