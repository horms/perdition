/**********************************************************************
 * io_select.h                                               March 2002
 * Horms                                             horms@vergenet.net
 *
 * Wrapper to allow select to deal with SSL buffering
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2002  Horms
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

#ifndef _PERDITION_IO_SELECT_H
#define _PERDITION_IO_SELECT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <vanessa_adt.h>

#include "io.h"

typedef vanessa_list_t io_select_t;


/**********************************************************************
 * io_select_create
 * Create a io_select_t
 * pre: none
 * post: io_select_t is allocated and set to NULL state
 * return: pointer to new io_select_t
 **********************************************************************/

io_select_t *io_select_create();
	

/**********************************************************************
 * io_select_destroy
 * Destroy an io_select_t
 * pre: s: io_select to destroy
 * post: s: s is destroyed
 * post: none
 **********************************************************************/

void io_select_destroy(io_select_t *s);


/**********************************************************************
 * io_select_add
 * Add an io to an io_select_t
 * pre: s: io_select_t to add io to
 *      io: io to add to s
 * post: io is added to s
 * return: s
 *         NULL on error
 **********************************************************************/

io_select_t *io_select_add(io_select_t *s, io_t *io);


/**********************************************************************
 * io_select_remove
 * Remove an io from the an io_select_t
 * pre: s: io_select_t to remove io from
 *      io: io to remove from io_select_t
 * post: io is removed from s, if it is in s
 * return: none
 **********************************************************************/

void io_select_remove(io_select_t *s, io_t *io);


/**********************************************************************
 * io_select_get
 * Get the io, stored in an io_select_t, which has fd as one
 * of its file descriptors. The first match will me returned.
 * The order is undefined :)
 * pre: s: io_select_t to retrieve io from
 *      fd: file descriptort to match
 * post: none
 * return: io matching fd
 *         NULL if not found or error
 **********************************************************************/

io_t *io_select_get(io_select_t *s, int fd);


/**********************************************************************
 * io_select
 * Wrapper around select which will probe fd's associated
 * with ssl connections for data internally buffered by
 * the SSL library
 * pre: n: The numerically highest file descriptor in readfds,
 *         writefds, and exceptfds, + 1
 *      readfds: file descriptors to test select for reading
 *      writefds: file descriptors to test select for writing
 *      exceptfds: file descriptors to test select for exceptions
 *      timeout: timeout. If NULL, then infinite timeout
 *      s: opaque data
 * post: has the same semantics as select()
 * return: number of active file descriptors found
 *         < 0 on error
 **********************************************************************/

int io_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	   struct timeval *timeout, void *data);

#endif /* _PERDITION_IO_SELECT_H */

