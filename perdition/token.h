/**********************************************************************
 * token.h                                               September 1999
 * Horms                                             horms@verge.net.au
 *
 * Token to encapsulate a byte string
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2004  Horms
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

#ifndef TOKEN_BLUM
#define TOKEN_BLUM

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <vanessa_socket.h>

#include "log.h"
#include "str.h"
#include "perdition_types.h"

#define BUFFER_SIZE (size_t)1024

#define TOKEN_DESTROY (void (*)(const void *))token_destroy
  
typedef struct{
  ssize_t n;
  unsigned char *buf;
  flag_t flag;
}token_t;

/*
 * Flags for Tokens
 */
#define TOKEN_NONE        (flag_t) 0x00   /* No flag (NULL state) */
#define TOKEN_EOL         (flag_t) 0x01   /* Token is at the end of a line */
#define TOKEN_DONT_CARE   (flag_t) 0x03   /* Don't care what token is.
					     Used for comparisons */

/*
 * Flags for tokeniser
 */
/* #define TOKEN_EOL, defined above */ 
#define TOKEN_POP3            (flag_t) 0x02
#define TOKEN_IMAP4           (flag_t) 0x04
#define TOKEN_IMAP4_LITERAL   (flag_t) 0x08

#define TOKEN_NO_STRIP    (unsigned char) '\0'

token_t *create_token(void);


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

token_t *token_create(void);


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
);


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

void token_unassign(token_t *t);


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

void token_destroy(token_t **t);


/**********************************************************************
 * token_write
 * write a token to fd
 * pre: io: io_t to write to
 *      token: token to write
 * post: contents of token is written to fd using 
 *       vanessa_socket_pipe_write_bytes
 * return: -1 on error
 *         0 otherwise
 *
 * 8 bit clean
 **********************************************************************/

int token_write(io_t *io, const token_t *t);


/**********************************************************************
 * token_flush
 * Flush internal buffers used to read tokens.
 * pre: none
 * post: internal buffers are flushed
 * return: none
 **********************************************************************/

void token_flush(void);


/**********************************************************************
 * token_read
 * read a token in from fd
 * pre: io: io_t to read from
 *      literal_buf: buffer to store bytes read from server in
 *      n: pointer to size_t containing the size of literal_buf
 *      flag: If logical or of TOKEN_EOL then all characters 
 *            up to a '\n' will be read as a token. That is the token may
 *            have spaces. 
 *            If logical or of TOKEN_IMAP4 then spaces inside
 *            quotes will be treated as literals rather than token
 *            delimiters.
 *            If logical or of TOKEN_IMAP4_LITERAL then m bytes 
 *            will be read as a single token.
 *      m: Bytes to read if flag is TOKEN_IMAP4_LITERAL
 *      log_str: logging tag for connection logging
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
 *       BUFFER_SIZE will be read and the remainder will be
 *       left (to be handled by an subsequent call to token_read).
 *       The same applies to *n if literal_buf is being filled.
 *
 * 8 bit clean
 **********************************************************************/

token_t *token_read(
  io_t *io,
  unsigned char *literal_buf, 
  size_t *n,
  flag_t flag,
  size_t m,
  const char *log_str
);


/**********************************************************************
 * token_is_eol
 * Check if the token is at the end of a line
 * pre: t: token to check eol flag of
 * post: none
 * return 1 if the token is at the end of a line
 *        0 otherwise
 **********************************************************************/

#define token_is_eol(_t) ((_t)->flag&TOKEN_EOL?1:0)


/**********************************************************************
 * token_buf
 * Get the buffer of a token
 * pre: t: token to get the buffer of
 * post: none
 * return: buffer of the token
 **********************************************************************/

#define token_buf(_t) ((_t)->buf)


/**********************************************************************
 * token_len
 * Get the length of a token
 * pre: t: token to get the length of
 * post: none
 * return: length of the token
 **********************************************************************/

#define token_len(_t) ((_t)->n)


/**********************************************************************
 * token_cmp
 * compare two tokens
 * pre: a: token to compare
 *      b: token to compare
 * post: none
 * return: 1 is they are the same
 *         0 otherwise
 * flag field will be ignored if either token has eol set to TOKEN_DONT_CARE
 *
 * Not 8 bit clean as it is case insensitive using toupper
 **********************************************************************/

int token_cmp(const token_t *a, const token_t *b);


/**********************************************************************
 * token_is_null
 * test if a token is null, that is has an empty payload
 * pre: t: token to test
 * post: none
 * return 1 if token is null
 *        0 otherwise
 * t->flag is ignored
 *
 * 8 bit clean
 **********************************************************************/

#define token_is_null(_t) ((_t)->n?0:1)


/**********************************************************************
 * token_to_string
 * dump the buffer in a token into a \0 terminated string
 * string will be dynamically allocated
 * pre: t: token to dump to a string
 *      strip: Character to strip from first and last character of 
 *             string if it is present. Ignored if TOKEN_NO_STRIP
 *
 * post: a string is allocated and the contents of it's buffer plus
 *       a trailing '\0' is placed in the string
 * return: the string
 *         NULL on error
 *
 * Not 8 bit clean
 **********************************************************************/

char *token_to_string(const token_t *t, const unsigned char strip);


#endif
