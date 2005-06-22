/**********************************************************************
 * pop3_out.h                                            September 1999
 * Horms                                             horms@verge.net.au
 *
 * Talk POP3 to an upstream server
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifndef _POP3_OUT_H
#define _POP3_OUT_H

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
 * pop3_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if neccessar0
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      pw:     structure with username and passwd
 *      tag:    ignored 
 *      protocol: protocol structure for POP3
 * post: Read the vreeting string from the server
 *       It tls_outgoing is set then issue the CAPA command
 *       and check for STLS capability.
 *       Note, that as many POP3 daemons do not impliment the CAPA
 *       command, the failure of this is not considered an error
 * return: Logical or of PROTOCOL_S_OK and
 *         PROTOCOL_S_STARTTLS if ssl_mode is tls_outgoing (or tls_all)
 *         and the STARTTLS capability was reported by the server
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int pop3_out_setup(
  io_t *rs_io,
  io_t *eu_io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol
);


/**********************************************************************
 * pop3_out_authenticate
 * Authenticate user with backend pop3 server
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      pw:     structure with username and passwd
 *      tag:    ignored 
 *      protocol: protocol structure for POP3
 *      buf: buffer to return server response in
 *      n: size of buffer
 * post: The USER and PASS commands are sent to the server
 * return: 1: on success
 *         0: on failure
 *        -1: on error
 **********************************************************************/

int pop3_out_authenticate(
  io_t *rs_io,
  io_t *eu_io,
  const struct passwd *pw,
  token_t *tag,
  const protocol_t *protocol,
  unsigned char *buf,
  size_t *n
);


/**********************************************************************
 * pop3_out_response
 * Compare a respnse from a server with the desired response
 * pre: rs_io: io to use to communicate with real server
 *      eu_io: io to use to communicate with end user
 *      tag: ignored
 *      desired_token: token expected from server
 *      buf: buffer to return server response in
 *      n: size of buffer
 * post: Response is read from the server
 * return: 1: tag and desired token found
 *         0: tag and desired token not found
 *        -1: on error
 **********************************************************************/

int pop3_out_response(
  io_t *rs_io,
  io_t *eu_io,
  const token_t *tag,
  const token_t *desired_token,
  vanessa_queue_t **q,
  unsigned char *buf,
  size_t *n
);


#endif /* _POP3_OUT_H */
