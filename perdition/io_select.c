#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <vanessa_adt.h>
#include <sys/select.h>

#ifdef WITH_SSL_SUPPORT
#include <openssl/ssl.h>
#endif

#include "io.h"
#include "log.h"
#include "io_select.h"

static int io_select_match_io(io_t *io, int *fd) {
	return((io_get_rfd(io) == *fd || io_get_wfd(io) == *fd)?0:1);
}

#define IO_SELECT_MATCH_IO (int (*)(void *, void *)) io_select_match_io


io_select_t *io_select_create()
{
	io_select_t *s;
	s = vanessa_list_create(1, NULL, NULL, NULL, NULL,
			        IO_SELECT_MATCH_IO, NULL);
	if(s == NULL) {
		PERDITION_DEBUG("vanessa_hash_create");
		return(NULL);
	}

	return(s);
}
	

void io_select_destroy(io_select_t *s) 
{
	vanessa_list_destroy(s);
}


io_select_t *io_select_add(io_select_t *s, io_t *io)
{
	s = vanessa_list_add_element(s, io);
	if(s == NULL) {
		PERDITION_DEBUG("vanessa_list_add_element");
		return(NULL);
	}

	return(s);
}


void io_select_remove(io_select_t *s, io_t *io) 
{
	vanessa_list_remove_element(s, io);
}


io_t *io_select_get(io_select_t *s, int fd)
{
	io_t *io;

	io = vanessa_list_get_element(s, &fd);
	if(io == NULL) {
		PERDITION_DEBUG("vanessa_list_get_element");
		return(NULL);
	}

	return(io);
}


#ifdef WITH_SSL_SUPPORT

static SSL *__io_select_get_ssl(io_select_t *s, int fd) {
	SSL *ssl;
	io_t *io;

	io = io_select_get(s, fd);
	if(io == NULL) {
		return(NULL);
	}

	ssl = io_get_ssl(io);

	return(ssl);
}

static int __io_select(int n, fd_set *readfds, fd_set *writefds, 
		       fd_set *exceptfds, struct timeval *timeout, 
		       io_select_t *s)
{
	int i;
	int pending = 0;
	int selected;
	fd_set want_readfds;
	fd_set want_writefds;
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

	/* Shortcut */
	if(!pending) {
		return(selected);
	}

	for(i = 0; i < n ; i++) {
		if(FD_ISSET(i, &want_readfds))
			FD_SET(i, readfds);
	}

	return(selected + pending);
}

#else

static int __io_select(int n, fd_set *readfds, fd_set *writefds, 
		       fd_set *exceptfds, struct timeval *timeout, 
		       io_select *s) 
{
	return(select(n, readfds, writefds, exceptfds, timeout));
}

#endif /* WITH_SSL_SUPPORT */

	
int io_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	   struct timeval *timeout, void *data) 
{
	return(__io_select(n, readfds, writefds, exceptfds, timeout,
				(io_select_t *)data));
}
