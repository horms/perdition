/**********************************************************************
 * pop3_out.h                                            September 1999
 * Horms                                             horms@vergenet.net
 *
 * Talk POP3 to an upstream server
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

#ifndef POP3_OUT_BLUM
#define POP3_OUT_BLUM

#include <pwd.h>
#include <sys/types.h>
#include <vanessa_adt.h>

#include "token.h"
#include "pop3_write.h"
#include "perdition_types.h"
#include "queue_func.h"
#include "protocol_t.h"
#include "greeting.h"


/**********************************************************************
 * pop3_out_authenticate
 * Authenticate user with backend pop3 server
 * pre: io: io_t to read from and write to
 *      pw:     structure with username and passwd
 *      tag:    ignored 
 *      protocol: protocol structure for POP3
 *      buf: buffer to return server response in
 *      n: size of buffer
 * post: 1: on success
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int pop3_out_authenticate(
  io_t *io,
  const struct passwd *pw,
  const token_t *tag,
  const protocol_t *protocol,
  unsigned char *buf,
  size_t *n
);
  

/**********************************************************************
 * pop3_out_response
 * Compare a respnse from a server with the desired response
 * pre: io: io_t to read from and write to
 *      out_fd: file descriptor to write to
 *      tag_string: ignored
 *      desired_token: token expected from server
 * post: 1 : tag and desired token found
 *       0: tag and desired token not found
 *       -1: on error
 **********************************************************************/


int pop3_out_response(
  io_t *io,
  const char *tag_string,
  const token_t *desired_token,
  vanessa_queue_t **q,
  unsigned char *buf,
  size_t *n
);

#endif
