/**********************************************************************
 * unix_socket.c                                              June 2003
 * Horms                                             horms@verge.net.au
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2004  Horms
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

#ifndef PERDITION_UNIX_SOCKET_H
#define PERDITION_UNIX_SOCKET_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "unix_socket.h"

#define PERDITION_UN_SERVER_SOCKET "/var/run/perdition.db"
#define PERDITION_UN_STR_LEN 108

typedef struct {
	char dir[PERDITION_UN_STR_LEN];
	char name[PERDITION_UN_STR_LEN];
	int fd;
} perdition_un_t;


void
perdition_un_close(perdition_un_t *un);

void 
perdition_un_init(perdition_un_t *un);

int 
perdition_un_send_recv(perdition_un_t *sock, perdition_un_t *peer, 
		void *msg, size_t send_len, size_t recv_len,
		int timeout, int retry);

#endif /* PERDITION_UNIX_SOCKET_H */

