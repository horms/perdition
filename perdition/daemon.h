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
 * Mail retrieval proxy server
 * Copyright (C) 1999-2001  Horms
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


/**********************************************************************
 * daemon_process
 * Close and fork to become a daemon.
 * Note: daemon_inetd_process should be called if the process is being
 * run from inetd.
 **********************************************************************/

void daemon_process(void);


/**********************************************************************
 * daemon_inetd_process
 * Chdir to and umask
 * This is all we really need to do if our process is run from
 * inetd
 **********************************************************************/

void daemon_inetd_process(void);


/**********************************************************************
 * daemon_become_child
 * Fork and exit from parent process. When we return 
 * we are our own clild. Very incestuous.
 **********************************************************************/

void daemon_become_child(void);


/**********************************************************************
 * daemon_close_fd
 * Close all the file descriptots a process has
 **********************************************************************/

void daemon_close_fd(void);


/**********************************************************************
 * daemon_setid
 * Set the userid and groupid of the process.
 * Arguments are the username or the userid as a string and 
 * the group or the groupid as a string.
 **********************************************************************/

int daemon_setid(const char *user, const char *group);


/**********************************************************************
 * daemon_exit_cleanly
 * If we get a sinal then close everthing, log it and quit
 **********************************************************************/

void daemon_exit_cleanly(int i);


/**********************************************************************
 * daemon_noop_handler
 * A signal handler that does nothing but reinstall itself
 * as the signal handler for the signal.
 * pre: sig: signal recieved by the process
 * post: signal handler reset for signal
 **********************************************************************/

void daemon_noop_handler(int sig);


#endif
