/**********************************************************************
 * io.c                                                        May 2001
 * Horms                                             horms@verge.net.au
 *
 * Abstraction layer to allow I/O to file descriptors or SSL objects
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


#ifndef _PERDITION_IO_H
#define _PERDITION_IO_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include "perdition_types.h"

typedef struct io_t_struct io_t;

typedef enum {
  io_type_fd,
#ifdef WITH_SSL_SUPPORT
  io_type_ssl,
#endif /* WITH_SSL_SUPPORT */
  io_type_none
} io_type_t;

enum io_err {
  io_err_none,
  io_err_other,
  io_err_timeout
};

/**********************************************************************
 * io_create_fd 
 * Create an io that uses fds
 * pre: read_fd: File descriptor for reading
 *      write_fd: File descriptor for writing
 *      name: name to associate with io
 * post: io_t is initialised to use fds
 * return: new io_t
 *         NULL on error
 **********************************************************************/

io_t *io_create_fd(int read_fd, int write_fd, const char *name);


#ifdef WITH_SSL_SUPPORT
#include <openssl/ssl.h>

/**********************************************************************
 * io_create_ssl 
 * Create an io that uses ssl
 * pre: ssl: SSL object
 *      read_fd: File descriptor for reading from
 *      write_fd: File descriptor for writing to
 *      name: name to associate with io
 * post: io_t is initialised to use ssl
 * return: new io_t
 *         NULL on error
 **********************************************************************/

io_t *io_create_ssl(SSL *ssl, int read_fd, int write_fd, const char *name);
#endif /* WITH_SSL_SUPPORT */


/**********************************************************************
 * io_destroy
 * Destroy and io_t
 * If it is an SSL io_t then call SSL_free()
 * pre: io: io_t to free
 * post: io and any internal data is freed
 * return: none
 **********************************************************************/

void io_destroy(io_t *io);


/**********************************************************************
 * io_write
 * Write to an io_t
 * pre: io: io_t to write to
 *      buf: buffer to write
 *      count: number of bytes to write
 * post: count byes from buffer are written to io
 * return: Number of bytes written
 *         -1 on error
 **********************************************************************/

ssize_t io_write(io_t *io, const void *buf, size_t count);


/**********************************************************************
 * io_read
 * Read from an io_t
 * pre: io: io_t to read from
 *      buf: buffer to read
 *      count: maximum number of bytes to read
 * post: up to count bytes are read from io into buf
 * return: Number of bytes read
 *         -1 on error
 **********************************************************************/

ssize_t io_read(io_t *io, void *buf, size_t count);


/**********************************************************************
 * io_get_rfd
 * Get the file descriptor that is being used for reading
 * pre: io: io_t to get read file descriptor of
 * post: none
 * return: file descriptor
 *         -1 on error
 **********************************************************************/

int io_get_rfd(io_t *io);


/**********************************************************************
 * io_get_wfd
 * Get the file descriptor that is being used for writing
 * pre: io: io_t to get write file descriptor of
 * post: none
 * return: file descriptor
 *         -1 on error
 **********************************************************************/

int io_get_wfd(io_t *io);


/**********************************************************************
 * io_get_type
 * Get type of an io
 * pre: io: io_t to get the type object of
 * post: none
 * return: type of io
 **********************************************************************/

io_type_t io_get_type(io_t *io);


/**********************************************************************
 * io_get_name
 * Get name of an io
 * pre: io: io_t to get the name of
 * post: none
 * return: name of the io (may be NULL)
 **********************************************************************/

const char *io_get_name(io_t *io);


/**********************************************************************
 * io_get_err
 * Get error status of an io
 * pre: io: io_t to setget the err of
 * post: none
 * return: error status of the io
 **********************************************************************/

enum io_err io_get_err(io_t *io);


/**********************************************************************
 * io_get_timoeut
 * Get the idle timeout of an io
 * pre: io: io_t to get the idle timeout of
 * post: none
 * return: timeout in seconds
 **********************************************************************/

long io_get_timeout(io_t *io);


/**********************************************************************
 * io_set_timoeut
 * Set the idle timeout of an io
 * pre: io: io_t to set the idle timeout of
 *      timeout: timeout in seconds, 0 for no timeout
 * post: idle timeout of the io_t is set
 * return: none
 **********************************************************************/

void io_set_timeout(io_t *io, long timeout);


/**********************************************************************
 * io_set_timoeut
 * Set the idle timeout of io
 * pre: io: io_t to set the idle timeout of
 *      timeout: timeout in seconds, 0 for no timeout
 * post: idle timeout of the io_t is set
 * return: none
 **********************************************************************/

void io_set_timeout(io_t *io, long timeout);


#ifdef WITH_SSL_SUPPORT
/**********************************************************************
 * io_get_ssl
 * Get ssl object for io, if there is one
 * pre: io: io_t to get the ssl object of
 * post: none
 * return: ssl object descriptor (may be NULL)
 *         NULL if there is no SSL object
 **********************************************************************/

SSL *io_get_ssl(io_t *io);
#endif /* WITH_SSL_SUPPORT */


/**********************************************************************
 * io_close
 * Close the file descriptors in an io_t
 * If it is an SSL io_t then call SSL_shutdown();
 * pre: io: io_t close the file descriptors of
 * post: file descriptors associated with ssl are closed
 *       or the ssl object is shutdown
 * return: 0 on success
 *         -1 on error
 **********************************************************************/

int io_close(io_t *io);


/**********************************************************************
 * io_pipe
 * pipe bytes from from one io_t to another and vice versa
 * pre: io_a: one of the io_t
 *      io_b: the other io_t
 *      buffer:   allocated buffer to read data into
 *      buffer_length: size of buffer in bytes
 *      return_a_read_bytes: Pointer to int where number
 *                           of bytes read from a will be recorded.
 *      return_b_read_bytes: Pointer to int where number
 *                           of bytes read from b will be recorded.
 * post: bytes are read from io_a and written to io_b and vice versa
 * return: -1 on error, including idle timeout
 *         0 otherwise (one of io_a or io_b closes gracefully)
 **********************************************************************/

ssize_t io_pipe(io_t *io_a, io_t *io_b, char *buffer,
		int buffer_length, size_t *return_a_read_bytes,
		size_t *return_b_read_bytes, timed_log_t *log);
#endif /* _PERDITION_IO_H */
