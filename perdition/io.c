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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <vanessa_socket.h>
#include <limits.h>

#include "io.h"
#include "io_select.h"
#include "log.h"
#include "options.h"
#include "perdition_types.h"
#include "perdition_globals.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


typedef struct {
  int read;
  int write;
} __io_fd_t;

#ifdef WITH_SSL_SUPPORT
typedef struct {
  int read;
  int write;
  SSL *ssl;
} __io_ssl_t;
#endif /* WITH_SSL_SUPPORT */

typedef union {
  void      *d_any;
  __io_fd_t *d_fd;
#ifdef WITH_SSL_SUPPORT
  __io_ssl_t *d_ssl;
#endif /* WITH_SSL_SUPPORT */
} __io_data_t;

struct io_t_struct {
  io_type_t type;
  __io_data_t data;
  char *name;
  enum io_err err;
  long timeout;
};


/**********************************************************************
 * __io_create
 * Create an shell io
 * pre: name: name to associate with io
 * post: shell of io_t is initialised 
 * return: new io_t
 *         NULL on error
 **********************************************************************/

static io_t *__io_create(const char *name){
  io_t *io;

  if((io=(io_t *)malloc(sizeof(io_t)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    free(io);
    return(NULL);
  }

  if(name) {
    io->name = strdup(name);
    if(!io->name) {
      VANESSA_LOGGER_DEBUG_ERRNO("strdup");
      free(io);
      return(NULL);
    }
  }
  else {
    io->name = NULL;
  }

  io->err = io_err_none;

  return(io);
}


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

io_t *io_create_fd(int read_fd, int write_fd, const char *name){
  __io_fd_t *io_fd;
  io_t *io;

  if((io_fd=(__io_fd_t *)malloc(sizeof(__io_fd_t)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    return(NULL);
  }

  io_fd->read=read_fd;
  io_fd->write=write_fd;

  if((io=__io_create(name)) == NULL) {
    VANESSA_LOGGER_DEBUG_ERRNO("__io_create");
    free(io_fd);
    return(NULL);
  }

  io->type=io_type_fd;
  io->data.d_fd=io_fd;

  return(io);
}


#ifdef WITH_SSL_SUPPORT
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

io_t *io_create_ssl(SSL *ssl, int read_fd, int write_fd, const char *name){
  __io_ssl_t *io_ssl;
  io_t *io;

  if((io_ssl=(__io_ssl_t *)malloc(sizeof(__io_ssl_t)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc 1");
    return(NULL);
  }

  SSL_set_rfd(ssl, read_fd);
  SSL_set_wfd(ssl, write_fd);

  io_ssl->ssl=ssl;
  io_ssl->read=read_fd;
  io_ssl->write=write_fd;

  if((io=__io_create(name)) == NULL) {
    VANESSA_LOGGER_DEBUG_ERRNO("__io_create");
    free(io_ssl);
    return(NULL);
  }

  io->type=io_type_ssl;
  io->data.d_ssl=io_ssl;

  return(io);
}
#endif /* WITH_SSL_SUPPORT */


/**********************************************************************
 * io_destroy
 * Destroy and io_t
 * If it is an SSL io_t then call SSL_free()
 * pre: io: io_t to free
 * post: io and any internal data is freed
 * return: none
 **********************************************************************/

void io_destroy(io_t *io){
  switch(io->type){
    case io_type_fd:
      if(io->data.d_fd != NULL) {
        free(io->data.d_fd);
      }
      io->data.d_fd = NULL;
      break;
#ifdef WITH_SSL_SUPPORT
    case io_type_ssl:
      if(io->data.d_ssl != NULL) {
        SSL_free(io->data.d_ssl->ssl);
        free(io->data.d_ssl);
        io->data.d_ssl = NULL;
      }
      break;
#endif /* WITH_SSL_SUPPORT */
    default:
      break;
  }

  if(io->name) {
    free(io->name);
  }

  free(io);
}


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

#ifdef WITH_SSL_SUPPORT
#define __IO_READ_WRITE_SSL_ERROR(_name, _ssl, _bytes) \
{ \
  int error; \
  error = SSL_get_error((_ssl), bytes); \
  PERDITION_DEBUG_SSL_IO_ERR(_name, (_ssl), _bytes); \
  if(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) { \
    VANESSA_LOGGER_DEBUG(_name ": Warning: wants read or write"); \
    return(0); \
  } \
  return(-1); \
}
#endif /* WITH_SSL_SUPPORT */

ssize_t io_write(io_t *io, const void *buf, size_t count){
  ssize_t bytes=0;

  switch(io->type){
    case io_type_fd:
      if((bytes=write(io->data.d_fd->write, buf, count))<0){
	VANESSA_LOGGER_DEBUG_ERRNO("write");
	goto err;
      }
      return bytes;
#ifdef WITH_SSL_SUPPORT
    case io_type_ssl:
      if((bytes=(ssize_t)SSL_write(io->data.d_ssl->ssl, buf, (int)count))<=0){
        if(bytes < 0) {
	  __IO_READ_WRITE_SSL_ERROR("SSL_write", io->data.d_ssl->ssl, bytes);
          goto err;
        }
        else
          return 0;
      }
      return bytes;
#endif /* WITH_SSL_SUPPORT */
    default:
      VANESSA_LOGGER_DEBUG("unknown io type");
      goto err;
   }

err:
  io->err = io_err_other;
  return -1;
}


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

ssize_t __io_read(io_t *io, void *buf, size_t count)
{
  ssize_t bytes=0;

  switch(io->type){
    case io_type_fd:
      if((bytes=read(io->data.d_fd->read, buf, count))<0){
	VANESSA_LOGGER_DEBUG_ERRNO("read");
	goto err;
      }
      return bytes;
#ifdef WITH_SSL_SUPPORT
    case io_type_ssl:
      if((bytes=(ssize_t)SSL_read(io->data.d_ssl->ssl, buf, (int)count))<=0){
        if(bytes < 0) {
	  __IO_READ_WRITE_SSL_ERROR("SSL_read", io->data.d_ssl->ssl, bytes);
          goto err;
        }
        else
          return 0;
      }
      return bytes;
#endif /* WITH_SSL_SUPPORT */
    default:
      VANESSA_LOGGER_DEBUG("unknown io type");
      goto err;
   }

err:
  io->err = io_err_other;
  return -1;
}


ssize_t io_read(io_t *io, void *buf, size_t count)
{
	io_select_t *s = NULL;
	struct timeval tv;
	fd_set except_template;
	fd_set read_template;
	int bytes_read;
	int status;
	int return_status = -1;
        int rfd;

        io->err = io_err_none;

        rfd = io_get_rfd(io);
        if (rfd < 0) {
		VANESSA_LOGGER_DEBUG("io_get_rfd");
		goto err;
	}

	s = io_select_create();
	if (s == NULL) {
		VANESSA_LOGGER_DEBUG("io_select_create");
		goto err;
	}

	if (!io_select_add(s, io)) {
		VANESSA_LOGGER_DEBUG("io_select_add");
		goto err_free;
	}

	while (1) {
		FD_ZERO(&read_template);
		FD_SET(rfd, &read_template);
		FD_ZERO(&except_template);
		FD_SET(rfd, &except_template);
		tv.tv_sec = io->timeout;
		tv.tv_usec = 0;

		status = io_select(FD_SETSIZE, &read_template, NULL,
                                   &except_template, io->timeout ? &tv : NULL,
                                   s);
		if (status < 0) {
			if (errno != EINTR) {
				VANESSA_LOGGER_DEBUG_ERRNO("select");
	                        goto err_free;
			}
			continue;	/* Ignore EINTR */
		}
		else if (FD_ISSET(rfd, &except_template)){
			VANESSA_LOGGER_DEBUG("error on file descriptor");
			goto err_free;
		}
		else if (!status) {
			VANESSA_LOGGER_DEBUG("idle timeout");
                        io->err = io_err_timeout;
                        goto err_free;
		}

		/* If we get this far fd must be ready for reading */
		bytes_read = __io_read(io, buf, count);
                if (bytes_read < 0) {
			if (errno != EINTR) {
			        VANESSA_LOGGER_DEBUG_ERRNO("error reading "
                                                           "input");
	                        goto err_free;
			}
			continue;	/* Ignore EINTR */
		}

                break;
	}

        return_status = bytes_read;
err_free:
        io_select_destroy(s);
err:
        if (return_status < 0 && io->err == io_err_none)
                io->err = io_err_other;
        return return_status;
}


/**********************************************************************
 * io_get_err
 * Get error status of an io
 * pre: io: io_t to get the err of
 * post: none
 * return: error status of the io
 **********************************************************************/

void io_set_err(io_t *io, enum io_err err);


/**********************************************************************
 * io_get_timoeut
 * Get the idle timeout of an io
 * pre: io: io_t to get the idle timeout of
 * post: none
 * return: timeout in seconds
 **********************************************************************/

long io_get_timeout(io_t *io)
{
        return io->timeout;
}


/**********************************************************************
 * io_set_timoeut
 * Set the idle timeout of an io
 * pre: io: io_t to set the idle timeout of
 *      timeout: timeout in seconds, 0 for no timeout
 * post: idle timeout of the io_t is set
 * return: none
 **********************************************************************/

void io_set_timeout(io_t *io, long timeout)
{
        io->timeout = timeout;
}


/**********************************************************************
 * io_get_rfd
 * Get the file descriptor that is being used for reading
 * pre: io: io_t to get read file descriptor of
 * post: none
 * return: file descriptor
 *         -1 on error
 **********************************************************************/

int io_get_rfd(io_t *io){
  switch(io->type){
    case io_type_fd:
      return io->data.d_fd->read;
#ifdef WITH_SSL_SUPPORT
    case io_type_ssl:
      return io->data.d_ssl->read;
#endif /* WITH_SSL_SUPPORT */
    default:
      VANESSA_LOGGER_DEBUG("unknown io type");
      goto err;
   }

err:
  io->err = io_err_other;
  return -1;
}


/**********************************************************************
 * io_get_wfd
 * Get the file descriptor that is being used for writing
 * pre: io: io_t to get write file descriptor of
 * post: none
 * return: file descriptor
 *         -1 on error
 **********************************************************************/

int io_get_wfd(io_t *io){
  switch(io->type){
    case io_type_fd:
      return io->data.d_fd->write;
#ifdef WITH_SSL_SUPPORT
    case io_type_ssl:
      return io->data.d_ssl->write;
#endif /* WITH_SSL_SUPPORT */
    default:
      VANESSA_LOGGER_DEBUG("unknown io type");
      goto err;
   }

err:
  io->err = io_err_other;
  return -1;
}


/**********************************************************************
 * io_get_type
 * Get type of an io
 * pre: io: io_t to get the type object of
 * post: none
 * return: type of io
 **********************************************************************/

io_type_t io_get_type(io_t *io){
  return(io->type);
}


/**********************************************************************
 * io_get_name
 * Get name of an io
 * pre: io: io_t to get the name of
 * post: none
 * return: name of the io (may be NULL)
 **********************************************************************/

const char *io_get_name(io_t *io){
  return(io->name);
}


/**********************************************************************
 * io_get_err
 * Get error status of an io
 * pre: io: io_t to get the err of
 * post: none
 * return: error status of the io
 **********************************************************************/

enum io_err io_get_err(io_t *io)
{
  return io->err;
}


#ifdef WITH_SSL_SUPPORT
/**********************************************************************
 * io_get_ssl
 * Get ssl object for io, if there is one
 * pre: io: io_t to get the ssl object of
 * post: none
 * return: ssl object descriptor (may be NULL)
 *         NULL if there is no SSL object
 **********************************************************************/

SSL *io_get_ssl(io_t *io){
  SSL *ssl;

  switch(io->type){
    case io_type_ssl:
      ssl=io->data.d_ssl->ssl;
      break;
    default:
      ssl=NULL;
      io->err = io_err_other;
      break;
   }
  
  return(ssl);
}
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

int io_close(io_t *io){
  int read_fd;
  int write_fd;

  if(io==NULL){
    VANESSA_LOGGER_DEBUG("NULL io");
    return(-1);
  }

  switch(io->type){
    case io_type_fd:

    read_fd=io_get_rfd(io);
    write_fd=io_get_wfd(io);
  
    if(close(read_fd)){
      VANESSA_LOGGER_DEBUG_ERRNO("close 1");
      goto err;
    }
    if(read_fd!=write_fd && close(write_fd)){
      VANESSA_LOGGER_DEBUG_ERRNO("close 2 %d %d");
      goto err;
    }

    break;;
#ifdef WITH_SSL_SUPPORT
    case io_type_ssl:
      /* 
       * This seems to return errors for no reason, so let's ignore them
       *
       * if(SSL_shutdown(io->data.d_ssl->ssl)<=0){
       *   PERDITION_DEBUG_SSL_ERR("SSL_shutdown");
       *   return(-1);
       * }
       */
      SSL_shutdown(io->data.d_ssl->ssl);
      break;
#endif /* WITH_SSL_SUPPORT */
    default:
      VANESSA_LOGGER_DEBUG("Unknown io type");
      goto err;
  }

  return(0);

err:
  io->err = io_err_other;
  return -1;
}


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

static int __io_pipe_read(int fd, void *buf, size_t count, void *data){
  io_t *io;
  io_select_t *s;
  ssize_t bytes;

  s=(io_select_t *)data;

  io=io_select_get(s, fd);
  if(io == NULL) {
	  VANESSA_LOGGER_DEBUG("io_select_get");
	  goto err;
  }

  io->err = io_err_none;

  bytes = __io_read(io, buf, count);

  if(opt.connection_logging && bytes > 0) {
    char *dump_str;
    dump_str = VANESSA_LOGGER_DUMP(buf, bytes, 0);
    if(!dump_str) {
      VANESSA_LOGGER_DEBUG("VANESSA_LOGGER_DUMP");
      goto err;
    }
    VANESSA_LOGGER_LOG_UNSAFE(LOG_DEBUG, "%s \"%s\"", 
		    str_null_safe(io_get_name(io)), dump_str);
    free(dump_str);
  }

  return(bytes);

err:
  if (io->err == io_err_none)
        io->err = io_err_other;
  return -1;
}
         

static int __io_pipe_write(int fd, const void *buf, size_t count, void *data){
  io_t *io;
  io_select_t *s;

  s=(io_select_t *)data;

  io=io_select_get(s, fd);
  if(io == NULL) {
	  VANESSA_LOGGER_DEBUG("io_select_get");
	  return(-1);
  }

  return(io_write(io, buf, count));
}

         
ssize_t io_pipe(io_t *io_a, io_t *io_b, char *buffer,
      int buffer_length, size_t *return_a_read_bytes,
      size_t *return_b_read_bytes, timed_log_t *log){
  int bytes;
  io_select_t *s;
  long timeout;

  if (io_a->timeout && io_b->timeout)
        timeout = io_a->timeout < io_b->timeout ? io_a->timeout :
                io_b->timeout;
  else if (io_a->timeout)
        timeout = io_a->timeout;
  else if (io_b->timeout)
        timeout = io_b->timeout;
  else
        timeout = 0;

  /* Cap timeout at INT_MAX, as vanessa_socket_pipe_func() takes
   * an integer as the timeout argument */
  if (timeout > INT_MAX)
        timeout = INT_MAX;

  s = io_select_create();
  if(s == NULL) {
	  VANESSA_LOGGER_DEBUG("io_select_create");
	  goto err;
  }

  s->log = log;

  if(io_select_add(s, io_a) == NULL || io_select_add(s, io_b) == NULL) {
	  VANESSA_LOGGER_DEBUG("io_select_add");
	  io_select_destroy(s);
          goto err;
  }

  if((bytes=vanessa_socket_pipe_func(io_get_rfd(io_a), io_get_wfd(io_a),
      io_get_rfd(io_b), io_get_wfd(io_b), buffer, buffer_length,
      timeout, return_a_read_bytes, return_b_read_bytes,
      __io_pipe_read, __io_pipe_write, io_select, (void *)s))<0){
	VANESSA_LOGGER_DEBUG("vanessa_socket_pipe_func");
        if (bytes == 1) {
            /* timeout */
            io_a->err = io_err_timeout;
            io_b->err = io_err_timeout;
        }
        goto err;
  }

  io_select_destroy(s);

  return(bytes);

err:
  if (io_a->err != io_err_none && io_b->err != io_err_none) {
            io_a->err = io_err_other;
            io_b->err = io_err_other;
  }
  return -1;
}
