/**********************************************************************
 * token.c                                               September 1999
 * Horms                                             horms@vergenet.net
 *
 * Token to encapsulate a byte string
 *
 * perdition
 * Mail retreival proxy server
 * Copyright (C) 1999  Horms
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


/**********************************************************************
 * create_token
 * create an empty token
 * pre: none
 * post: token is created, and values are initialised 
 * return: allocated token_t
 *         NULL on error
 *
 * 8 bit clean
 **********************************************************************/

token_t *create_token(void){
  token_t *t;

  if((t=(token_t *)malloc(sizeof(token_t)))==NULL){
    PERDITION_LOG(LOG_DEBUG, "create_token: malloc");
    return(NULL);
  }
  t->n=0;
  t->buf=NULL;
  return(t);
}


/**********************************************************************
 * assign_token
 * place bytes into a token
 * pre: t: token to place bytes in
 *      buf: buffer to use
 *      n: number of bytes in buffer
 *      eol: status to set eol flag to
 * post: if n!=0 then buf is used as the buffer in t
 *       (no copying)
 *       if n==0 the buffer in t is set to NULL
 *       the eol flag in t is set to eol
 * return: none
 *
 * 8 bit clean
 **********************************************************************/

void assign_token(
  token_t *t, 
  unsigned char * buf, 
  const ssize_t n,
  const int eol
){
  t->n=n;
  t->eol=eol;
  if(n==0){
    t->buf=NULL;
  }
  else {
    t->buf=buf;
  }
}


/**********************************************************************
 * unassign_token
 * make a token empty
 * useful if you want to destroy a token but not what it contains
 * pre: t: token to unasign values of
 * post: values in t are reinitialised, but buffer is not destroyed
 * return: none
 *
 * 8 bit clean
 **********************************************************************/

void unassign_token(token_t *t){
  assign_token(t, (unsigned char *)NULL, (ssize_t)0, 0);
}


/**********************************************************************
 * destroy_token
 * pre: t pointer to a token
 * post: if the token is null no nothing
 *       if buf is non-NULL then free it
 *       free the token
 * return: none
 *
 * 8 bit clean
 **********************************************************************/

void destroy_token(token_t **t){
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
 * write_token
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

int write_token(const int fd, const token_t *t){
  if(vanessa_socket_pipe_write_bytes(fd, t->buf, t->n)){
    PERDITION_LOG(LOG_DEBUG, "write_token: write_strn");
    return(-1);
  }
  
  return(0);
}


/**********************************************************************
 * read_token
 * read a token in from fd
 * pre: fd: file descriptor to read from
 *      literal_buf: buffer to store bytes read from server in
 *      n: pointer to size_t containing the size of literal_buf
 * post: Token is read from fd into token
 *       ' ' will terminate a token
 *       '\r' is ignored
 *       '\"' is ignored (weird thing netscape imap client sends)
 *       '\n' will terminate a token and set the eol element to 1
 *       All other characters are considered to be a part of the token
 *       If literal_buf is not NULL, and n is not NULL and *n is not 0
 *       Bytes read from fd are copied to literal_buf, this includes
 *       ' ', '\r' '\"' and '\n'.
 * return: token
 *         NULL on error
 * Note: if a token larger than BUFFER_SIZE is read then only
 *       BUFFER_SIZE will be read and the remander will be
 *       left (to be handled by an sbsequent call to read_token).
 *       The same appies to *n if literal_buf is being filled.
 *
 * 8 bit clean
 **********************************************************************/

token_t *read_token(const int fd, unsigned char *literal_buf, size_t *n){
  struct timeval timeout;
  unsigned char *buffer;
  token_t *t;
  size_t literal_offset=0;
  size_t offset=0;
  fd_set except_template;
  fd_set read_template;
  int bytes_read;
  int do_literal;
  int status;
  int eol=0;

  extern options_t opt;

  if((buffer=(unsigned char*)malloc(sizeof(unsigned char)*BUFFER_SIZE))==NULL){
    PERDITION_LOG(LOG_DEBUG, "read_token: malloc buffer: %s", strerror(errno));
    return(NULL);
  }

  do_literal=(literal_buf!=NULL && n!=NULL && *n!=0)?1:0;
  while(offset<BUFFER_SIZE && !(do_literal && literal_offset>=*n)){
    FD_ZERO(&read_template);
    FD_SET(fd, &read_template);
    FD_ZERO(&except_template);
    FD_SET(fd, &except_template);
    timeout.tv_sec=opt.timeout;
    timeout.tv_usec=0;

    status=select(
      FD_SETSIZE,
      &read_template,
      NULL,
      &except_template,
      opt.timeout?&timeout:NULL
    );
    if(status<0){
      if(errno!=EINTR){
        PERDITION_LOG(LOG_DEBUG, "read_token: select: %s", strerror(errno));
        daemon_exit_cleanly(-1);
      }
      continue;  /* Ignore EINTR */
    }
    else if(FD_ISSET(fd, &except_template)){
      PERDITION_LOG(LOG_DEBUG, "read_token: error on file descriptor");
      goto leave;
    }
    else if(status==0){
      PERDITION_LOG(LOG_DEBUG, "read_token: idle timeout");
      daemon_exit_cleanly(0);
    }

    /*If we get this far fd must be ready for reading*/
    if((bytes_read=read(fd, buffer+offset, 1))<0){
      PERDITION_LOG(LOG_DEBUG, "read_token: error reading input", strerror(errno));
      goto leave;
    }
    if(bytes_read==0){
      goto leave;
    }

    /*Place in literal buffer, if we are doooooooooooooing that today*/
    if(do_literal){
      *(literal_buf+(literal_offset++))=*(buffer+offset);
    }

    if(*(buffer+offset)=='\n'){
      eol=1;
      break;
    }
    else if(*(buffer+offset)=='\r'){
      continue;
    }
    else if(*(buffer+offset)=='\"'){
      continue;
    }
    else if(*(buffer+offset)==' '){
      break;
    }
    else{
      offset++;
    }
  }

  /*Set return value for n*/
  *n=literal_offset;

  /*Create token to return*/
  if((t=create_token())==NULL){
    PERDITION_LOG(LOG_DEBUG, "read_token: create_token");
    goto leave;
  }
  assign_token(t, buffer, offset, eol);
  return(t);

  /*Escape hatch if something goes wrong*/
  leave:
  free(buffer);
  return(NULL);
}


/**********************************************************************
 * token_is_eol
 * Check if the token is at the end of a line
 * pre: t: token to check eol flag of
 * post: none
 * return 1 if the token is at the end of a line
 *        0 otherwise
 **********************************************************************/

int token_is_eol(const token_t *t){
  return(t->eol);
}


/**********************************************************************
 * token_cmp
 * compare two tokens
 * pre: a: token to compare
 *      b: token to compare
 * post: none
 * return: 1 is they are the same
 *         0 otherwise
 * eol field will be ignored if eiter token has eol set to -1 (don't care)
 *
 * Not 8 bit clean as it is case insensitive using toupper
 **********************************************************************/

int token_cmp(const token_t *a, const token_t *b){
  int i;

  if(a->n!=b->n){
    return(0);
  }

  if((a->eol!=b->eol) && (a->eol>-1) && (b->eol>-1)){
    return(0);
  }

  for(i=0;i<a->n;i++){
    if(toupper(*(a->buf+i))!=toupper(*(b->buf+i))){
      return(0);
    }
  }

  return(1);
}


/**********************************************************************
 * token_is_null
 * test if a token is null, that is has an empty payload
 * pre: t: token to test
 * post: none
 * return 0 if token is null
 *        -1 otherwise
 * eol field is ignored
 *
 * 8 bit clean
 **********************************************************************/

int token_is_null(const token_t *t){
  return(t->n==0?0:-1);
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
