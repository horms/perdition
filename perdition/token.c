/**********************************************************************
 * token.c                                               September 1999
 * Horms                                             horms@vergenet.net
 *
 * Token to encapsulate a byte string
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

#include "token.h"
#include "options.h"


static unsigned char token_read_buffer[MAX_LINE_LENGTH];
static size_t token_read_offset=0;
static size_t token_read_bytes=0;

static int token_fill_buffer(const int fd, const options_t *opt);
static int __token_fill_buffer(const int fd, const options_t *opt);


/**********************************************************************
 * token_create
 * create an empty token
 * pre: none
 * post: token is created, and values are initialised 
 * return: allocated token_t
 *         NULL on error
 *
 * 8 bit clean
 **********************************************************************/

token_t *token_create(void){
  token_t *t;

  if((t=(token_t *)malloc(sizeof(token_t)))==NULL){
    PERDITION_LOG(LOG_DEBUG, "token_create: malloc");
    return(NULL);
  }
  t->n=0;
  t->buf=NULL;
  return(t);
}


/**********************************************************************
 * token_assign
 * place bytes into a token
 * pre: t: token to place bytes in
 *      buf: buffer to use
 *      n: number of bytes in buffer
 *      flags: flags for token as per token.h
 * post: if n!=0 then buf is used as the buffer in t
 *       (no copying)
 *       if n==0 the buffer in t is set to NULL
 *       the flag in t is set
 * return: none
 *
 * 8 bit clean
 **********************************************************************/

void token_assign(
  token_t *t, 
  unsigned char * buf, 
  const size_t n,
  const flag_t flag
){
  t->n=n;
  t->flag=flag;
  if(n==0){
    if(buf!=NULL){
      free(buf);
    }
    t->buf=NULL;
  }
  else {
    t->buf=buf;
  }
}


/**********************************************************************
 * token_unassign
 * make a token empty
 * useful if you want to destroy a token but not what it contains
 * pre: t: token to unassign values of
 * post: values in t are reinitialised, but buffer is not destroyed
 * return: none
 *
 * 8 bit clean
 **********************************************************************/

void token_unassign(token_t *t){
  token_assign(t, (unsigned char *)NULL, (size_t)0, 0);
}


/**********************************************************************
 * token_destroy
 * pre: t pointer to a token
 * post: if the token is null no nothing
 *       if buf is non-NULL then free it
 *       free the token
 * return: none
 *
 * 8 bit clean
 **********************************************************************/

void token_destroy(token_t **t){
  if(*t==NULL){
    return;
  }

  if((*t)->buf!=NULL){
    free((*t)->buf);
  }

  free(*t);
  *t=NULL;
}


/**********************************************************************
 * token_write
 * write a token to fd
 * pre: fd: File descriptor to write to
 *      token: token to write
 * post: contents of token is written to fd using 
 *       vanessa_socket_pipe_write_bytes
 * return: -1 on error
 *         0 otherwise
 *
 * 8 bit clean
 **********************************************************************/

int token_write(const int fd, const token_t *t){
  if(vanessa_socket_pipe_write_bytes(fd, t->buf, t->n)){
    PERDITION_LOG(LOG_DEBUG, "token_write: vanessa_socket_pipe_write_bytes");
    return(-1);
  }
  
  return(0);
}


/**********************************************************************
 * token_fill_buffer
 * read a token in from fd
 * pre: fd: file descriptor to read from
 *      opt: options
 * post: Bytes are read from fd into a buffer, if the buffer is
 *       empty
 * return: number of bytes read, or number of uread bytes in buffer
 *         -1 on error
 *
 * 8 bit clean
 **********************************************************************/

static int token_fill_buffer(const int fd, const options_t *opt) {
  if(token_read_bytes>token_read_offset) {
    if(token_read_bytes==0){
      PERDITION_DEBUG("token_fill_buffer: returning without read");
    }  
    return(token_read_bytes);
  }
  return(__token_fill_buffer(fd, opt));
}

static int __token_fill_buffer(const int fd, const options_t *opt){
  struct timeval timeout;
  fd_set except_template;
  fd_set read_template;
  int bytes_read;
  int status;

  while(1){
    FD_ZERO(&read_template);
    FD_SET(fd, &read_template);
    FD_ZERO(&except_template);
    FD_SET(fd, &except_template);
    timeout.tv_sec=opt->timeout;
    timeout.tv_usec=0;

    status=select(
      FD_SETSIZE, 
      &read_template, 
      NULL, 
      &except_template,
      opt->timeout?&timeout:NULL
    );
    if(status<0){
      if(errno!=EINTR){
        PERDITION_DEBUG_ERRNO("token_fill_buffer: select:", errno);
        return(-1);
      }
      continue;  /* Ignore EINTR */
    }
    else if(FD_ISSET(fd, &except_template)){
      PERDITION_DEBUG("token_fill_buffer: error on file descriptor");
      return(-1);
    }
    else if(status==0){
      PERDITION_DEBUG("token_fill_buffer: idle timeout");
      return(0);
    }

    /*If we get this far fd must be ready for reading*/
    if((bytes_read=read(fd, token_read_buffer, MAX_LINE_LENGTH-1))<0){
      PERDITION_DEBUG_ERRNO("token_fill_buffer: error reading input", errno);
      return(-1);
    }

    if(bytes_read==0){
      PERDITION_DEBUG_ERRNO("token_fill_buffer: zero bytes read", errno);
    }

    token_read_offset=0;
    token_read_bytes=bytes_read;
    return(bytes_read);
  }

  PERDITION_DEBUG("token_fill_buffer: fall-through return\n");
  return(0); /* Here to stop compiler complaining */
}


/**********************************************************************
 * token_read
 * read a token in from fd
 * pre: fd: file descriptor to read from
 *      literal_buf: buffer to store bytes read from server in
 *      n: pointer to size_t containing the size of literal_buf
 * post: Token is read from fd into token
 *       ' ' will terminate a token
 *       '\r' is ignored
 *       '\n' will terminate a token and set the eol element to 1
 *       All other characters are considered to be a part of the token
 *       If literal_buf is not NULL, and n is not NULL and *n is not 0
 *       Bytes read from fd are copied to literal_buf, this includes
 *       ' ', '\r' and '\n'.
 * return: token
 *         NULL on error
 * Note: if a token larger than BUFFER_SIZE is read then only
 *       BUFFER_SIZE will be read and the remander will be
 *       left (to be handled by an sbsequent call to token_read).
 *       The same appies to *n if literal_buf is being filled.
 *
 * 8 bit clean
 **********************************************************************/

token_t *token_read(const int fd, unsigned char *literal_buf, size_t *n){
  unsigned char buffer[MAX_LINE_LENGTH];
  unsigned char *assign_buffer;
  unsigned char c;
  token_t *t;
  size_t literal_offset=0;
  size_t len=0;
  size_t offset=0;
  int bytes_read;
  int do_literal;
  flag_t flag=TOKEN_NONE;

  extern options_t opt;

  do_literal=(literal_buf!=NULL && n!=NULL && *n!=0)?1:0;
  while(!(do_literal && literal_offset>=*n)){
    if((bytes_read=token_fill_buffer(fd, &opt))<=0){
      PERDITION_DEBUG("token_read: token_fill_buffer");
      return(NULL);
    }

    c=token_read_buffer[token_read_offset++];

    /*Place in literal buffer, if we are doooooooooooooing that today*/
    if(do_literal){
      *(literal_buf+(literal_offset++))=c;
    }

    switch(c){
      case '\n':
        flag=TOKEN_EOL;
        goto end_while;
      case '\r':
        break;
      case ' ':
        goto end_while;
      default:
        buffer[len++]=c;
    }
  }
end_while:

  /*Set return value for n*/
  if(do_literal){
    *n=literal_offset;
  }

  /*Unquote quoted strings if we are in imap4 mode*/
  if(opt.protocol==PROTOCOL_IMAP4 && *buffer=='\"' && *(buffer+len-1)=='\"'){
    offset++;
    len--;
    flag|=TOKEN_HAS_QUOTES;
  }

  /*Create token to return*/
  if((t=token_create())==NULL){
    PERDITION_LOG(LOG_DEBUG, "token_read: token_create");
    return(NULL);
  }
  if((assign_buffer=(unsigned char*)malloc(len-offset))==NULL){
    PERDITION_DEBUG_ERRNO("token_read: malloc", errno);
    return(NULL);
  }
  memcpy(assign_buffer, buffer+offset, len-offset);
  token_assign(t, assign_buffer, len-offset, flag);
  return(t);
}


/**********************************************************************
 * token_cmp
 * compare two tokens
 * pre: a: token to compare
 *      b: token to compare
 * post: none
 * return: 1 is they are the same
 *         0 otherwise
 * flag field will be ignored if eiter token has eol set to TOKEN_DONT_CARE
 *
 * Not 8 bit clean as it is case insensitive using toupper
 **********************************************************************/

int token_cmp(const token_t *a, const token_t *b){
  if(
    a->n!=b->n ||
    ((a->flag!=b->flag)&&(a->flag!=TOKEN_DONT_CARE)&&(b->flag!=TOKEN_DONT_CARE))
  ){
    return(0);
  }

  return(strncasecmp(a->buf, b->buf, a->n)?0:1);
}


/**********************************************************************
 * token_to_string
 * dump the buffer in a token into a \0 terminated string
 * string will be dynamically allocated
 * pre: t: token to dump to a string
 * post: a sting is allocated and the contents of t's buffer pluss
 *       a trailing '\0' is placed in the string
 * return: the string
 *         NULL on error
 *
 * Not 8 bit clean
 **********************************************************************/

char *token_to_string(const token_t *t){
  char *string;

  if((string=strn_to_str((char *)t->buf, t->n))==NULL){
    PERDITION_LOG(LOG_DEBUG, "token_to_string: strn_to_str");
    return(NULL);
  }
  return(string);
}
