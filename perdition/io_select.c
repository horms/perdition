/**********************************************************************
 * io_select.c                                               March 2002
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

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <vanessa_adt.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef WITH_SSL_SUPPORT
#include <openssl/ssl.h>
#endif

#include "io.h"
#include "log.h"
#include "options.h"
#include "io_select.h"


/**********************************************************************
 * io_select_match_io
 * Match an io structure based on an fd
 * pre: io: io to match fd of
 *      fd: fd to match
 * post: none
 * return: 0 if fd is one of the file descriptors for io
 *         1 otherwise
 **********************************************************************/

static int io_select_match_io(io_t *io, int *fd) {
	return((io_get_rfd(io) == *fd || io_get_wfd(io) == *fd)?0:1);
}

#define IO_SELECT_MATCH_IO (int (*)(void *, void *)) io_select_match_io


/**********************************************************************
 * io_select_create
 * Create a io_select_t
 * pre: none
 * post: io_select_t is allocated and set to NULL state
 * return: pointer to new io_select_t
 **********************************************************************/

io_select_t *io_select_create()
{
	io_select_t *s;
	s = calloc(1, sizeof(io_select_t));
	if(!s) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc");
		return(NULL);
	}

	s->fd = vanessa_list_create(1, NULL, NULL, NULL, NULL,
			        IO_SELECT_MATCH_IO, NULL);
	if(s->fd == NULL) {
		VANESSA_LOGGER_DEBUG("vanessa_list_create");
		free(s);
		return(NULL);
	}

	return(s);
}
	

/**********************************************************************
 * io_select_destroy
 * Destroy an io_select_t
 * pre: s: io_select to destroy
 * post: s: s is destroyed
 * post: none
 **********************************************************************/

void io_select_destroy(io_select_t *s) 
{
	vanessa_list_destroy(s->fd);
	free(s);
}


/**********************************************************************
 * io_select_add
 * Add an io to an io_select_t
 * pre: s: io_select_t to add io to
 *      io: io to add to s
 * post: io is added to s
 * return: s
 *         NULL on error
 **********************************************************************/

io_select_t *io_select_add(io_select_t *s, io_t *io)
{
	s->fd = vanessa_list_add_element(s->fd, io);
	if(s->fd == NULL) {
		VANESSA_LOGGER_DEBUG("vanessa_list_add_element");
		return(NULL);
	}

	return(s);
}


/**********************************************************************
 * io_select_remove
 * Remove an io from the an io_select_t
 * pre: s: io_select_t to remove io from
 *      io: io to remove from io_select_t
 * post: io is removed from s, if it is in s
 * return: none
 **********************************************************************/

void io_select_remove(io_select_t *s, io_t *io) 
{
	vanessa_list_remove_element(s->fd, io);
}


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

io_t *io_select_get(io_select_t *s, int fd)
{
	io_t *io;

	io = vanessa_list_get_element(s->fd, &fd);
	if(io == NULL) {
		VANESSA_LOGGER_DEBUG("vanessa_list_get_element");
		return(NULL);
	}

	return(io);
}


#ifdef WITH_SSL_SUPPORT

/**********************************************************************
 * __io_select_get_ssl
 * Get the ssl object associated with an fd, by first searching
 * an io_select_t for a matching io, and then returning the corresponding
 * ssl structure, if there is one.
 * pre: s: io_select structure to search 
 *      fd: file descriptor to match
 * post: none
 * return: ssl structure if found
 *         NULL otherwise
 **********************************************************************/

static SSL *__io_select_get_ssl(io_select_t *s, int fd) {
	SSL *ssl;
	io_t *io;

	io = io_select_get(s, fd);
	if(io == NULL) {
		return(NULL);
	}
	if(io_get_type(io) != io_type_ssl) {
		return(NULL);
	}

	ssl = io_get_ssl(io);

	return(ssl);
}
#endif /* WITH_SSL_SUPPORT */


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

static int __io_select(int n, fd_set *readfds, fd_set *writefds, 
		       fd_set *exceptfds, struct timeval *timeout, 
		       io_select_t *s)
{
#ifdef WITH_SSL_SUPPORT
	int i;
	int pending = 0;
	int selected;
	fd_set want_readfds;
	struct timeval zero_timeout; 
	SSL *ssl;
	FD_ZERO(&want_readfds);

	if(readfds != NULL) {
		for(i = 0; i < n ; i++) {
			if(!(FD_ISSET(i, readfds))) {
				continue;
			}
			ssl = __io_select_get_ssl(s, i);
			if(ssl == NULL)
				continue;
			if (SSL_pending(ssl)) {
				FD_SET(i, &want_readfds);
				pending++;
			}
		}
	}

	zero_timeout.tv_sec = 0;
	zero_timeout.tv_usec = 0;
	
	selected = select(n, readfds, writefds, exceptfds, 
			pending?&zero_timeout:timeout);

	/* Jump out if there was an error */
	if(selected < 0) {
		return(selected);
	}

	/* Shortcut */
	if(!pending) {
		return(selected);
	}

	for(i = 0; i < n ; i++) {
		if(FD_ISSET(i, &want_readfds) && !FD_ISSET(i, readfds)) {
			FD_SET(i, readfds);
			selected++;
		}
	}

	return(selected);
#else /* WITH_SSL_SUPPORT */
	return(select(n, readfds, writefds, exceptfds, timeout));
#endif /* WITH_SSL_SUPPORT */
}

int io_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	   struct timeval *timeout, void *data) 
{
	int status;
	io_select_t *s;
	time_t now;
	time_t relog;
	fd_set readfds_save;
	fd_set writefds_save;
	fd_set exceptfds_save;
	struct timeval internal_timeout;

	extern options_t opt;

	s = (io_select_t *)data;
	relog = (s && s->log && opt.connect_relog) ? s->log->log_time : 0;

	if(readfds) {
		memcpy(&readfds_save, readfds, sizeof(fd_set));
	}
	if(writefds) {
		memcpy(&writefds_save, writefds, sizeof(fd_set));
	}
	if(exceptfds) {
		memcpy(&exceptfds_save, exceptfds, sizeof(fd_set));
	}

	while(1) {
		now = time(NULL);
		if(timeout) {
			internal_timeout.tv_sec = timeout->tv_sec;
			internal_timeout.tv_usec = timeout->tv_usec;
		}
		if(relog && now >= s->log->log_time) {
			VANESSA_LOGGER_LOG(LOG_NOTICE, s->log->log_str);
			s->log->log_time = now + opt.connect_relog;
		}
		if(relog && (!timeout || internal_timeout.tv_sec > 
				s->log->log_time - now)) {
			internal_timeout.tv_sec = s->log->log_time - now;
			internal_timeout.tv_usec = 0;
			if(timeout) {
				timeout->tv_sec -= s->log->log_time - now;
			}
		}
		else if (timeout) {
			timeout->tv_sec = 0;
			timeout->tv_usec = 0;
		}
	
		if(readfds) {
			memcpy(readfds, &readfds_save, sizeof(fd_set));
		}
		if(writefds) {
			memcpy(writefds, &writefds_save, sizeof(fd_set));
		}
		if(exceptfds) {
			memcpy(exceptfds, &exceptfds_save, sizeof(fd_set));
		}
		status = __io_select(n, readfds, writefds, 
				exceptfds, &internal_timeout, s);
		if(status || (timeout && !timeout->tv_sec 
					&& !timeout->tv_usec)) {
			break;
		}
	}

	timeout->tv_sec += internal_timeout.tv_sec;
	timeout->tv_usec += internal_timeout.tv_usec;

	return(status);
}
