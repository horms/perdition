/**********************************************************************
 * imap4_out.h                                           September 1999
 * Horms                                             horms@vergenet.net
 *
 * Functions to communicate with upstream IMAP4 server
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

#ifndef _IMAP4_OUT_H
#define _IMAP4_OUT_H

#include <pwd.h>
#include <sys/types.h>
#include <vanessa_adt.h>

#include "token.h"
#include "imap4_write.h"
#include "perdition_types.h"
#include "str.h"
#include "greeting.h"
#include "queue_func.h"
#include "protocol_t.h"


/**********************************************************************
 * imap4_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if neccessary.
 * pre: io: io_t to read from and write to
 *      pw:     structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structiure for imap4
 * post: Read the greeting string from the server
 *       If tls_outgoing is set issue the CAPABILITY command and check
 *       for the STARTTLS capability.
 * return: Logical or of PROTOCOL_S_OK and
 *         PROTOCOL_S_STARTTLS if ssl_mode is tls_outgoing (or tls_all)
 *         and the STARTTLS capability was reported by the server
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int imap4_out_setup(
  io_t *io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol
);


/**********************************************************************
 * imap4_authenticate
 * Authenticate user with backend imap4 server
 * You should call imap4_setup() first
 * pre: io: io_t to read from and write to
 *      pw:     structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structiure for imap4
 *      buf:    buffer to return response from server in
 *      n:      size of buf in bytes
 * post: The CAPABILITY command is sent to the server and the result is read
 *       If the LOGINDISABLED capability is set porocessing stops
 *       Otherwise the LOGIN command is sent and the result is checked
 * return: 2: if the server has the LOGINDISABLED capability set
 *         1: on success
 *         0: on failure
 *        -1: on error
 **********************************************************************/

int imap4_out_authenticate(
  io_t *io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol,
  unsigned char *buf,
  size_t *n
);


/**********************************************************************
 * imap4_out_response
 * Compare a respnse from a server with the desired response
 * pre: io: io_t to read from
 *      tag_string: tag expected from server
 *      desired_token: token expected from server
 *      q: resulting queue is stored here
 *      buf: buffer to read server response in to
 *      n: size of buf
 * post: Response is read from the server
 * return: 1 : tag and desired token found
 *         0: tag and desired token not found
 *         -1: on error
 **********************************************************************/

int imap4_out_response(
  io_t *io,
  const char *tag_string,
  const token_t *desired_token,
  vanessa_queue_t **q,
  unsigned char *buf,
  size_t *n
);

#endif /* _IMAP4_OUT_H */

