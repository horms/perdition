/**********************************************************************
 * token.h                                               September 1999
 * Horms                                             horms@vergenet.net
 *
 * Token to encapsulate a byte string
 *
 * perdition
 * Mail retrieval proxy server
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
#include "daemon.h"

#define BUFFER_SIZE (size_t)1024

#define DESTROY_TOKEN (void (*)(const void *))destroy_token
  
typedef struct{
  ssize_t n;
  unsigned char * buf;
  int eol;
}token_t;

token_t *create_token(void);

void assign_token(
  token_t *t, 
  unsigned char * buf, 
  const ssize_t n, 
  const int eol
);

void unassign_token(token_t *t);

void destroy_token(token_t **t);

int write_token(const int fd, const token_t *t);

token_t *read_token(const int fd, unsigned char *literal_buf, size_t *n);

int token_is_eol(const token_t *t);

int token_cmp(const token_t *a, const token_t *b);

int token_is_null(const token_t *t);

char *token_to_string(const token_t *t);

#endif
