/**********************************************************************
 * io.c                                                        May 2001
 * Horms                                             horms@vergenet.net
 *
 * Abstraction layer to allow I/O to file descriptors or SSL objects
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <vanessa_socket.h>

#include "io.h"
#include "io_select.h"
#include "log.h"

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

typedef enum {
  __io_fd,
#ifdef WITH_SSL_SUPPORT
  __io_ssl,
#endif /* WITH_SSL_SUPPORT */
  __io_none
} io_type_t;

struct io_t_struct {
  io_type_t type;
  __io_data_t data;
};


/**********************************************************************
 * io_create_fd 
 * Create an io that uses fds
 * pre: read_fd: File descriptor for reading
 *      write_fd: File descriptor for writing
 * post: io_t is intialised to use fds
 * return: new io_t
 *         NULL on error
 **********************************************************************/

io_t *io_create_fd(int read_fd, int write_fd){
  __io_fd_t *io_fd;
  io_t *io;

  if((io_fd=(__io_fd_t *)malloc(sizeof(__io_fd_t)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc 1");
    return(NULL);
  }

  io_fd->read=read_fd;
  io_fd->write=write_fd;

  if((io=(io_t *)malloc(sizeof(io_t)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc 2");
    free(io_fd);
    return(NULL);
  }

  io->type=__io_fd;
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
 * post: io_t is intialised to use ssl
 * return: new io_t
 *         NULL on error
 **********************************************************************/

io_t *io_create_ssl(SSL *ssl, int read_fd, int write_fd){
  __io_ssl_t *io_ssl;
  io_t *io;

  if((io_ssl=(__io_ssl_t *)malloc(sizeof(__io_ssl_t)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc 1");
    return(NULL);
  }

  SSL_set_rfd(ssl, read_fd);
  SSL_set_wfd(ssl, write_fd);

  io_ssl->ssl=ssl;
  io_ssl->read=read_fd;
  io_ssl->write=write_fd;

  if((io=(io_t *)malloc(sizeof(io_t)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc 2");
    free(io_ssl);
    return(NULL);
  }

  io->type=__io_ssl;
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
  if(io==NULL){
    return;
  }

  switch(io->type){
    case __io_fd:
      if(io->data.d_fd != NULL) {
        free(io->data.d_fd);
      }
      io->data.d_fd = NULL;
      break;
#ifdef WITH_SSL_SUPPORT
    case __io_ssl:
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
  free(io);
}


/**********************************************************************
 * io_write
 * Write to an io_t
 * pre: io: io_t to write to
 *      buf: buffer to write
 *      count: number of bytes to write
 * return: Number of bytes written
 *         -1 on error
 **********************************************************************/

ssize_t io_write(io_t *io, const void *buf, size_t count){
  ssize_t bytes=0;

  if(io==NULL){
    PERDITION_DEBUG("NULL io");
    return(-1);
  }

  switch(io->type){
    case __io_fd:
      if((bytes=write(io->data.d_fd->write, buf, count))<0){
	PERDITION_DEBUG_ERRNO("write");
	return(-1);
      }
      break;
#ifdef WITH_SSL_SUPPORT
    case __io_ssl:
      if((bytes=(ssize_t)SSL_write(io->data.d_ssl->ssl, buf, (int)count))<=0){
        if(bytes==0 && errno &&
            SSL_get_error(io->data.d_ssl->ssl, bytes)==SSL_ERROR_SYSCALL){
          PERDITION_DEBUG_ERRNO("SSL_write");
	  return(-1);
        }
        else {
          return(0);
        }
      }
      break;
#endif /* WITH_SSL_SUPPORT */
    default:
      PERDITION_DEBUG("unknown io type");
      bytes=-1;
      break;
   }
  
  return(bytes);
}


/**********************************************************************
 * io_read
 * Read from an io_t
 * pre: io: io_t to read from
 *      buf: buffer to read
 *      count: maximum number of bytes to read
 * return: Number of bytes read
 *         -1 on error
 **********************************************************************/

ssize_t io_read(io_t *io, void *buf, size_t count){
  ssize_t bytes=0;

  if(io==NULL){
    PERDITION_DEBUG("NULL io");
    return(-1);
  }

  switch(io->type){
    case __io_fd:
      if((bytes=read(io->data.d_fd->read, buf, count))<0){
	PERDITION_DEBUG_ERRNO("read");
	return(-1);
      }
      break;
#ifdef WITH_SSL_SUPPORT
    case __io_ssl:
      if((bytes=(ssize_t)SSL_read(io->data.d_ssl->ssl, buf, (int)count))<=0){
        if(bytes==0 && errno &&
            SSL_get_error(io->data.d_ssl->ssl, bytes)==SSL_ERROR_SYSCALL){
          PERDITION_DEBUG_ERRNO("SSL_read");
	  return(-1);
        }
        else {
          return(0);
        }
      }
      break;
#endif /* WITH_SSL_SUPPORT */
    default:
      PERDITION_DEBUG("unknown io type");
      bytes=-1;
      break;
   }
  
  return(bytes);
}


/**********************************************************************
 * io_get_rfd
 * Get the file descriptor that is being used for reading
 * pre: io: io_t to get read file descriptor of
 * return: file descriptor
 *         -1 on error
 **********************************************************************/

int io_get_rfd(io_t *io){
  int fd;

  if(io==NULL){
    PERDITION_DEBUG("NULL io");
    return(-1);
  }

  switch(io->type){
    case __io_fd:
      fd=io->data.d_fd->read;
      break;
#ifdef WITH_SSL_SUPPORT
    case __io_ssl:
      fd=io->data.d_ssl->read;
      break;
#endif /* WITH_SSL_SUPPORT */
    default:
      PERDITION_DEBUG("unknown io type");
      fd=-1;
      break;
   }
  
  return(fd);
}


/**********************************************************************
 * io_get_wfd
 * Get the file descriptor that is being used for writing
 * pre: io: io_t to get write file descriptor of
 * return: file descriptor
 *         -1 on error
 **********************************************************************/

int io_get_wfd(io_t *io){
  int fd;

  if(io==NULL){
    PERDITION_DEBUG("NULL io");
    return(-1);
  }

  switch(io->type){
    case __io_fd:
      fd=io->data.d_fd->write;
      break;
#ifdef WITH_SSL_SUPPORT
    case __io_ssl:
      fd=io->data.d_ssl->write;
      break;
#endif /* WITH_SSL_SUPPORT */
    default:
      PERDITION_DEBUG("unknown io type");
      fd=-1;
      break;
   }
  
  return(fd);
}


#ifdef WITH_SSL_SUPPORT
/**********************************************************************
 * io_get_ssl
 * Get ssl object for io, if there is one
 * pre: io: io_t to get the ssl object of
 * return: ssl object descriptor
 *         NULL on error if if there is no ssl object for this io
 **********************************************************************/

SSL *io_get_ssl(io_t *io){
  SSL *ssl;

  if(io==NULL){
    PERDITION_DEBUG("NULL io");
    return(NULL);
  }

  switch(io->type){
    case __io_ssl:
      ssl=io->data.d_ssl->ssl;
      break;
    default:
      PERDITION_DEBUG("No SSL object for io");
      ssl=NULL;
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
 * return: 0 on success
 *         -1 on error
 **********************************************************************/

int io_close(io_t *io){
  int read_fd;
  int write_fd;

  if(io==NULL){
    PERDITION_DEBUG("NULL io");
    return(-1);
  }

  switch(io->type){
    case __io_fd:

    read_fd=io_get_rfd(io);
    write_fd=io_get_wfd(io);
  
    if(close(read_fd)){ \
      PERDITION_DEBUG_ERRNO("close 1"); \
      return(-1); \
    } \
    if(read_fd!=write_fd && close(write_fd)){ \
      PERDITION_DEBUG_ERRNO("close 2 %d %d"); \
      return(-1); \
    }

    break;;
#ifdef WITH_SSL_SUPPORT
    case __io_ssl:
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
      PERDITION_DEBUG("Unknown io type");
      return(-1);
  }

  return(0);
}


/**********************************************************************
 * io_pipe
 * pipe bytes from from one io_t to another ance vice versa
 * pre: io_a: one of the io_t
 *      io_b: the other io_t
 *      buffer:   allocated buffer to read data into
 *      buffer_length: size of buffer in bytes
 *      idle_timeout:  timeout in seconds to wait for input
 *                     timeout of 0 = infinite timeout
 *      return_a_read_bytes: Pointer to int where number
 *                           of bytes read from a will be recorded.
 *      return_b_read_bytes: Pointer to int where number
 *                           of bytes read from b will be recorded.
 * bytes are read from io_a and written to io_b and vice versa
 * return: -1 on error
 *         1 on idle timeout
 *         0 otherwise (one of io_a or io_b closes gracefully)
 *
 **********************************************************************/

static int __io_pipe_read(int fd, void *buf, size_t count, void *data){
  io_t *io;
  io_select_t *s;

  s=(io_select_t *)data;

  io=io_select_get(s, fd);
  if(io == NULL) {
	  PERDITION_DEBUG("io_select_get");
	  return(-1);
  }

  return(io_read(io, buf, count));
}
         

static int __io_pipe_write(int fd, const void *buf, size_t count, void *data){
  io_t *io;
  io_select_t *s;

  s=(io_select_t *)data;

  io=io_select_get(s, fd);
  if(io == NULL) {
	  PERDITION_DEBUG("io_select_get");
	  return(-1);
  }

  return(io_write(io, buf, count));
}

         
ssize_t io_pipe(
  io_t *io_a,
  io_t *io_b,
  unsigned char *buffer,
  int buffer_length,
  int idle_timeout,
  int *return_a_read_bytes,
  int *return_b_read_bytes
){
  int bytes;
  io_select_t *s;

  s = io_select_create();
  if(s == NULL) {
	  PERDITION_DEBUG("io_select_create");
	  return(-1);
  }

  if(io_select_add(s, io_a) == NULL || io_select_add(s, io_b) == NULL) {
	  PERDITION_DEBUG("io_select_add");
	  io_select_destroy(s);
	  return(-1);
  }

  if((bytes=vanessa_socket_pipe_func(io_get_rfd(io_a),
    				     io_get_wfd(io_a),
    				     io_get_rfd(io_b),
    				     io_get_wfd(io_b),
    				     buffer,
    				     buffer_length,
    				     idle_timeout,
    				     return_a_read_bytes,
    				     return_b_read_bytes,
    				     __io_pipe_read,
    				     __io_pipe_write,
    				     io_select,
    				     (void *)s))<0){
	PERDITION_DEBUG("vanessa_socket_pipe_func");
  }

  io_select_destroy(s);

  return(bytes);
}
