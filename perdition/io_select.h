#ifndef _IO_SELECT_H
#define _IO_SELECT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <vanessa_adt.h>
#include <sys/select.h>

#include "io.h"

typedef vanessa_list_t io_select_t;

io_select_t *io_select_create();

void io_select_destroy(io_select_t *s);

io_select_t *io_select_add(io_select_t *s, io_t *io);

void io_select_remove(io_select_t *s, io_t *io);

io_t *io_select_get(io_select_t *s, int fd);
	
int io_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	   struct timeval *timeout, void *data);

#endif /* _IO_SELECT_H */

