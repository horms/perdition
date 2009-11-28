/**********************************************************************
 * imap4_out.h                                           September 1999
 * Horms                                             horms@verge.net.au
 *
 * Functions to communicate with upstream IMAP4 server
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
 * the connection is ok and doing TLS if necessary.
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      pw:     structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structure for imap4
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
  io_t *rs_io,
  io_t *eu_io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol
);


/**********************************************************************
 * imap4_authenticate
 * Authenticate user with back-end imap4 server
 * You should call imap4_setup() first
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      pw:     structure with username and passwd
 *      tag:    tag to use when authenticating with back-end server
 *      protocol: protocol structure for imap4
 *      buf:    buffer to return response from server in
 *      n:      size of buf in bytes
 * post: The CAPABILITY command is sent to the server and the result is read
 *       If the LOGINDISABLED capability is set processing stops
 *       Otherwise the LOGIN command is sent and the result is checked
 * return: 2: if the server has the LOGINDISABLED capability set
 *         1: on success
 *         0: on failure
 *        -1: on error
 **********************************************************************/

int imap4_out_authenticate(
  io_t *rs_io,
  io_t *eu_io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol,
  char *buf,
  size_t *n
);


/**********************************************************************
 * imap4_out_response
 * Compare a response from a server with the desired response
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      tag: tag expected from server. NULL for untagged.
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
  io_t *rs_io,
  io_t *eu_io,
  const token_t *tag,
  const token_t *desired_token,
  vanessa_queue_t **q,
  char *buf,
  size_t *n
);

#endif /* _IMAP4_OUT_H */

