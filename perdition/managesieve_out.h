#ifndef PERDITION_MANAGESIEVE_OUT_H
#define PERDITION_MANAGESIEVE_OUT_H

#include "io.h"
#include "token.h"
#include "protocol_t.h"

#include <pwd.h>

/**********************************************************************
 * managesieve_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if necessary.
 * pre: rs_io: io to use to communicate with real server
 *	eu_io: io to use to communicate with end user
 *	auth:  structure with authentication credentials
 *	tag:    ignored
 * post: Read the greeting string from the server
 *	 If tls_outgoing is set issue the CAPABILITY command and check
 *	 for the STARTTLS capability.
 * return: Logical or of PROTOCOL_S_OK and
 *	   PROTOCOL_S_STARTTLS if ssl_mode is tls_outgoing (or tls_all)
 *	   and the STARTTLS capability was reported by the server
 *	 0: on failure
 *	 -1 on error
 **********************************************************************/

int managesieve_out_setup(io_t *rs_io, io_t *eu_io, const struct auth *auth,
			  token_t *tag);

/**********************************************************************
 * managesieve_authenticate
 * Authenticate user with back-end managesieve server
 * You should call managesieve_setup() first
 * pre: rs_io: io to use to communicate with real server
 *	eu_io: io to use to communicate with end user
 *	auth:    structure with authentication credentials
 *	tag:    ignored
 *	protocol: protocol structure for managesieve
 *	buf:    buffer to return response from server in
 *	n:      size of buf in bytes
 * post: The CAPABILITY command is sent to the server and the result is read
 *	 If the desired SASL mechanism is not available then processing stops.
 *	 Otherwise the AUTHENTICATE command is sent and the result is checked
 * return: 2: if the server does not support the desired SASL mechanism
 *	   1: on success
 *	   0: on failure
 *	   -1: on error
 **********************************************************************/

int managesieve_out_authenticate(io_t *rs_io, io_t *eu_io,
				 const struct auth *auth, token_t *tag,
				 const protocol_t *protocol,
				 char *buf, size_t *n);

/**********************************************************************
 * managesieve_out_response
 * Compare a response from a server with the desired response
 * pre: rs_io: io to use to communicate with real server
 *	eu_io: io to use to communicate with end user
 *	tag: ignored
 *	desired_token: token expected from server
 *	q: resulting queue is stored here
 *	buf: buffer to read server response in to
 *	n: size of buf
 * post: Response is read from the server
 * return: 1 : tag and desired token found
 *	   0: tag and desired token not found
 *	   -1: on error
 **********************************************************************/

int managesieve_out_response(io_t *rs_io, io_t *eu_io, const token_t *tag,
			     const token_t *desired_token, vanessa_queue_t **q,
			     char *buf, size_t *n);

#endif /* PERDITION_MANAGESIEVE_OUT_H */

