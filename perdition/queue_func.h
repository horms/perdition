/**********************************************************************
 * queue_func.h                                            October 1999
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

#ifndef QUEUE_FUNC_FLIM
#define QUEUE_FUNC_FLIM

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <vanessa_adt.h>

#include "log.h"
#include "str.h"
#include "perdition_types.h"
#include "daemon.h"
#include "token.h"


/**********************************************************************
 * read_line
 * read a line from fd and parse it into a queue of tokens
 * line is read by making repeated calls to token_read
 * pre: io: io_t to read from
 *      buf: buffer to store bytes read from server in
 *      n: pointer to size_t containing the size of literal_buf
 *      flag: Flags. Will be passed to token_read().
 *            If logical or of TOKEN_POP3 (and anything else) then other
 *            than for the first token read on a line flags will be
 *            logically ored with TOKEN_EOL before passing to token_read().
 *            That is, in POP3 mode the second token read may include
 *            spaces and will cover all characters to the end of the line.
 * post: Token is read from fd into token
 *       If literal_buf is not NULL, and n is not NULL and *n is not 0
 *       Bytes read from fd are copied to literal_buf.
 * return: token
 *         NULL on error
 * Note: If buf is being filled and space is exausted function will
 *       return what has been read so far. (No buffer overflows today)
 **********************************************************************/


vanessa_queue_t *read_line(
  io_t *io,
  unsigned char *buf, 
  size_t *n,
  flag_t flag
);


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

char *queue_to_string(vanessa_queue_t *q);

#endif
