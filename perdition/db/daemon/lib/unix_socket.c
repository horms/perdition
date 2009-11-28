/**********************************************************************
 * unix_socket.c                                              June 2003
 * Horms                                             horms@verge.net.au
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif


#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vanessa_logger.h>

#include "unix_socket.h"

void
perdition_un_close(perdition_un_t *un)
{
	if (un->fd >= 0) {
		close(un->fd);
	}
	if (*(un->name)) {
		unlink(un->name);
	}
	if (*(un->dir)) {
		rmdir(un->dir);
	}
}

void 
perdition_un_init(perdition_un_t *un)
{
	un->fd = -1;
	memset(un->dir, 0, PERDITION_UN_STR_LEN);
	memset(un->name, 0, PERDITION_UN_STR_LEN);
}


int 
perdition_un_send_recv(perdition_un_t *sock, perdition_un_t *peer, 
		void *msg, size_t send_len, size_t recv_len,
		int timeout, int retry)
{
	struct sockaddr_un unaddr;
	ssize_t bytes;
	int rc;
	socklen_t socklen;
	fd_set readfd;
	struct timeval to;
	int attempt;
	int pause;

	attempt = 0;
resend:
	pause = timeout;
	for(; attempt < retry ; attempt++) {
		socklen = sizeof(struct sockaddr_un);
		memset(&unaddr, 0, socklen);
		unaddr.sun_family = AF_UNIX;
		strncpy(unaddr.sun_path, peer->name, PERDITION_UN_STR_LEN-1);

		/* VANESSA_LOGGER_DEBUG_UNSAFE("sending %d bytes to %s "
				"(retry %d)", send_len, unaddr.sun_path,
				attempt);
				*/
		bytes = sendto(sock->fd, msg, send_len, 0, 
				(struct sockaddr *) &unaddr, socklen);
		if(bytes < 0 || (size_t)bytes != send_len) {
			if(errno == EINTR) {
				attempt--;
				continue;
			}
			if(errno == ENOENT || errno == ECONNREFUSED) {
				if(attempt < retry-1) {
					sleep(pause);
					pause *= 2;
				}
				continue;
			}
			VANESSA_LOGGER_DEBUG_ERRNO("sendto");
			return(-1);
		}
		break;
	}

	if (attempt >= retry) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Giving up after %d retries",
				attempt);
		return(-1);
	}

	pause = timeout;
	for(;;) {
		FD_ZERO(&readfd);
		FD_SET(sock->fd, &readfd);
		to.tv_sec = pause;
		to.tv_usec = 0;

		rc = select(sock->fd + 1, &readfd, NULL, NULL, &to);
		if(rc < 0) {
			if(errno == EINTR) {
				continue;
			}
			VANESSA_LOGGER_DEBUG_ERRNO("select");
			return(-1);
		}
		if(rc == 0) {
			/* Timeout */
			pause *= 2;
			goto resend;
		}

		socklen = sizeof(struct sockaddr_un);
		memset(&unaddr, 0, socklen);

		bytes = recvfrom(sock->fd, msg, recv_len, 0,
				(struct sockaddr *) &unaddr, &socklen);
		if(bytes < 0) {
			if(errno == EINTR) {
				continue;
			}
			VANESSA_LOGGER_DEBUG_ERRNO("recvfrom");
			return(-1);
		}

		/*
		VANESSA_LOGGER_DEBUG_UNSAFE("%d bytes recieved from %s", 
				bytes, unaddr.sun_path);
				*/
		if(strcmp(unaddr.sun_path, peer->name)) {
			VANESSA_LOGGER_DEBUG("not from server, ignoring");
			continue;
		}

		break;
	}

	return(bytes);
}
