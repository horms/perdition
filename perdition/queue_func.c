/**********************************************************************
 * queue_func.c                                            October 1999
 * Horms                                             horms@vergenet.net
 *
 * Functions build around the queue ADT
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
#include "config.h"
#endif

#include "queue_func.h"
#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif



/**********************************************************************
 * read_line
 * read a line from fd and parse it into a queue of tokens
 * line is read by making repeated calls to token_read
 * pre: io: io_t to read from
 *      buf: buffer to store bytes read from server in
 *      n: pointer to size_t containing the size of literal_buf
 *      flag: Flags. Will be passed to token_read().
 *      m: Will be passed to token_read().
 * post: Token is read from fd into token
 *       If literal_buf is not NULL, and n is not NULL and *n is not 0
 *       Bytes read from fd are copied to literal_buf.
 * return: token
 *         NULL on error
 * Note: If buf is being filled and space is exausted function will
 *       return what has been read so far. (No buffer overflows today)
 **********************************************************************/

static vanessa_queue_t *__read_line(
  io_t *io,
  unsigned char *buf, 
  size_t *n,
  flag_t flag,
  size_t m
){
  token_t *t=NULL;
  size_t buf_offset=0;
  size_t buf_remaining;
  vanessa_queue_t *q;
  int do_literal;

  if(buf!=NULL && n!=NULL && *n!=0){
    do_literal=1;
    buf_remaining=*n;
  }
  else{
    buf=NULL;
    buf_remaining=0;
    do_literal=0;
  }

  if((q=vanessa_queue_create(TOKEN_DESTROY))==NULL){
    PERDITION_DEBUG("create_queue");
    return(NULL);
  }
 
  do{
    if(flag&TOKEN_POP3 && vanessa_queue_length(q)){
      flag|=TOKEN_EOL;
    }

    if((t=token_read(
      io,
      (buf==NULL)?NULL:buf+buf_offset,
      &buf_remaining,
      flag,
      m
    ))==NULL){
      PERDITION_DEBUG("token_read");
      vanessa_queue_destroy(q);
      return(NULL);
    }

    if(do_literal){
      buf_offset+=buf_remaining;
      buf_remaining=*n-buf_offset;
    }

    if((q=vanessa_queue_push(q, (void *)t))==NULL){
      PERDITION_DEBUG("vanessa_queue_push");
      return(NULL);
    }
  }while(
    !(flag&TOKEN_IMAP4_LITERAL) && 
    !token_is_eol(t) && 
    !(do_literal && buf_offset>=*n)
  );

  if(do_literal){
    *n=buf_offset;
  }

  return(q);
}

vanessa_queue_t *read_line(
  io_t *io, 
  unsigned char *buf, 
  size_t *n, 
  flag_t flag,
  size_t m
){
  int do_literal=0;
  char *local_buf;
  size_t local_n;
  vanessa_queue_t *local_q;

  extern int errno;
  extern options_t opt;

  if(opt.connection_logging){
    if(buf!=NULL && n!=NULL && *n!=0){
      do_literal=1;
    }

    if(!do_literal){
      if((local_buf=(char *)malloc(MAX_LINE_LENGTH*sizeof(char)))==NULL){
        PERDITION_DEBUG_ERRNO("malloc");
        return(NULL);
      }
      local_n=MAX_LINE_LENGTH-1;
    }
    else{
      local_buf=buf;
      local_n=(*n)-1;
    }

    if((local_q=__read_line(io, local_buf, &local_n, flag, m))==NULL){
      PERDITION_DEBUG("__read_line");
      if(!do_literal){
        free(local_buf);
      }
      return(NULL);
    }

    *(local_buf+local_n)='\0';

    if(!do_literal){
      free(local_buf);
    }
    else{
      *n=local_n;
    }
    return(local_q);
  }

  /* Fast Path :) */
  return(__read_line(io, buf, n, flag, m));

}


/**********************************************************************
 * queue_to_string
 * convert the contents of a queue of tokens into a string
 * a space ( ) is inserted in the resultant string between each
 * token
 * pre: q queue to dump as a string
 * post: a string is allocated and the quie is dumped to the string
 *       the string is '\0' terminated
 * return: allocated string
 *         NULL on error
 **********************************************************************/

char *queue_to_string(vanessa_queue_t *q){
  token_t *t;
  vanessa_queue_t *stack=NULL;
  size_t length=0;
  char *string;
  char *pos;

  if((stack=vanessa_queue_create(TOKEN_DESTROY))==NULL){
    PERDITION_DEBUG("create_queue");
    return(NULL);
  }

  while(vanessa_queue_pop(q, (void **)&t)!=NULL) {
    length+=1+t->n;

    if((stack=vanessa_queue_push(stack, (void *)t))==NULL){
      PERDITION_DEBUG("vanessa_queue_push");
      return(NULL);
    }
  }

  vanessa_queue_destroy(q);

  if((string=(char*)malloc(sizeof(char)*length))==NULL){
    PERDITION_DEBUG("malloc");
    vanessa_queue_destroy(stack);
    return(NULL);
  }

  pos = string;
  while(vanessa_queue_pop(stack, (void **)&t)!=NULL){
    if (t->n>0 && t->buf!=NULL){
      strncpy(pos, t->buf, t->n);
      pos+=t->n;
      *pos++=' ';
    }
  }
  
  vanessa_queue_destroy(stack);
  *--pos='\0';

  return(string);
}
