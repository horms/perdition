#include "acap_token.h"
#include "auth.h"
#include "io.h"
#include "token.h"
#include "protocol.h"
#include "protocol_t.h"
#include "perdition_globals.h"
#include "queue_func.h"
#include "str.h"
#include "sasl_plain.h"
#include "managesieve_out.h"
#include "managesieve_write.h"
#include "unused.h"

static int read_ok(io_t *rs_io, io_t *eu_io, char *buf, size_t *n)
{
	token_t ok;
	vanessa_queue_t *q = NULL;
	int status;

	token_assign(&ok, MANAGESIEVE_OK,
		     strlen(MANAGESIEVE_OK), TOKEN_DONT_CARE);

	status = managesieve_out_response(rs_io, eu_io, NULL, &ok, &q, buf, n);
	if (status < 0)
		VANESSA_LOGGER_DEBUG("pop3_out_response");

	vanessa_queue_destroy(q);
	return status;
}

/**********************************************************************
 * managesieve_out_read_capability
 * Read capability from real-server.
 * This may be the initial greeting or the response to a CAPABILITY command
 * pre: rs_io: io to use to communicate with real server
 * post: Read the input from the server
 * return:
 *       non-zero: success, will be the logical or of PROTOCOL_S_OK and any of:
 *	   PROTOCOL_S_STARTTLS: use STARTTLS
 *	   PROTOCOL_S_SASL_PLAIN: has SASL PLAIN
 *       0: on failure
 *       -1 on error
 **********************************************************************/

int managesieve_out_capability(io_t *rs_io)
{
	vanessa_queue_t *q = NULL;
	STRUCT_ACAP_TOKEN_WRAPPER_STATUS(wrapper_status);
	int status = -1, protocol_status = PROTOCOL_S_OK;
	int is_capability = 1, is_sasl = 0;

	while (1) {
		if (!q) {
			q = read_line(rs_io, NULL, NULL, TOKEN_MANAGESIEVE, 0,
				      PERDITION_LOG_STR_REAL);
			if (!q) {
				VANESSA_LOGGER_DEBUG("read_line");
				goto err;;
			}
		}

		wrapper_status = acap_token_wrapper(rs_io, PERDITION_SERVER, q);
		q = wrapper_status.q; /* acap_token_wrapper() consumes q */

		if (wrapper_status.status == -2) {
			VANESSA_LOGGER_DEBUG("acap_token_wrapper 2");
			goto err;
		} else if (wrapper_status.status == -1)
			goto err;

		if (wrapper_status.type == acap_atom)
			break;

		if (is_capability) {
			if (!strcmp(wrapper_status.str,
				    MANAGESIEVE_CMD_STARTTLS))
				protocol_status |= PROTOCOL_S_STARTTLS;
			else if (!strcmp(wrapper_status.str, "SASL"))
				is_sasl = 1;
		} else if (is_sasl)
			if (!strcaseword(wrapper_status.str,
					 SASL_MECHANISM_PLAIN))
				protocol_status |= PROTOCOL_S_SASL_PLAIN;

		if (acap_token_wrapper_status_is_eol(&wrapper_status)) {
			is_capability = 1;
			is_sasl = 0;
		}
		else
			is_capability = 0;

		free(wrapper_status.str);
		wrapper_status.str = NULL;
	}

	if (strcmp(wrapper_status.str, MANAGESIEVE_OK)) {
		status = 0;
		goto err;
	}

	status = protocol_status;
err:
	vanessa_queue_destroy(q);
	free(wrapper_status.str);
	return status;
}

/**********************************************************************
 * managesieve_out_setup
 * Begin interaction with real server by checking that
 * the connection is ok and doing TLS if necessary.
 * pre: rs_io: io to use to communicate with real server
 *	eu_io: io to use to communicate with end user
 *	auth:  structure with authentication credentials
 *	tag:    ignored
 * post: Read the greeting string from the real-server.
 *       Send an STARTTLS command if the ssl_mode is tls_outgoing
 *       or tls_outgoing_force and the STARTTLS is supported by the
 *       real-server.
 * return:
 *	  non-zero: success, will be the logical or of PROTOCOL_S_OK and any of:
 *	   PROTOCOL_S_STARTTLS: STARTTLS has been issued
 *	   PROTOCOL_S_SASL_PLAIN: has SASL PLAIN
 *	 0: on failure
 *	 -1 on error
 **********************************************************************/

int managesieve_out_setup(io_t *rs_io, io_t *eu_io,
			  const struct auth *UNUSED(auth),
			  token_t *UNUSED(tag))
{
	int status, server_status;

	status = managesieve_out_capability(rs_io);
	if (status < 1) {
		VANESSA_LOGGER_DEBUG("managesieve_out_capability");
		return status;
	}

	if (!(opt.ssl_mode & SSL_MODE_TLS_OUTGOING))
		return status ^= PROTOCOL_S_STARTTLS;

	if (!(status & PROTOCOL_S_STARTTLS)) {
		if (opt.ssl_mode & SSL_MODE_TLS_OUTGOING_FORCE) {
			VANESSA_LOGGER_DEBUG_RAW("tls_outgoing_force "
						 "is set, but the "
						 "real-server does "
						 "not have the STARTTLS "
						 "capability, "
						 "closing connection");
			return -1;
		}
		VANESSA_LOGGER_DEBUG_RAW("tls_outgoing is set, but the "
					 "real-server does not have the "
					 "STARTTLS capability, connection "
					 "will not be encrypted");
		return status;
	}

	if (managesieve_write(rs_io, PERDITION_CLIENT,
			      MANAGESIEVE_CMD_STARTTLS, NULL, NULL) < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_write");
		return -1;
	}

	server_status = read_ok(rs_io, eu_io, NULL, 0);
	if (server_status < 1) {
		VANESSA_LOGGER_DEBUG("read_ok");
		return server_status;
	}

	return status;
}

/**********************************************************************
 * managesieve_authenticate
 * Authenticate user with back-end managesieve server
 * You should call managesieve_setup() first
 * pre: rs_io: io to use to communicate with real server
 *	eu_io: io to use to communicate with end user
 *	tls_state: the current state of encryption for the session
 *	auth:    structure with authentication credentials
 *	sasl_mech: sasl_mechanisms reported by real-server
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

int managesieve_out_authenticate(io_t *UNUSED(rs_io), io_t *UNUSED(eu_io),
				 flag_t UNUSED(tls_state),
				 const struct auth *UNUSED(auth),
				 flag_t UNUSED(sasl_mech),
				 token_t *UNUSED(tag),
				 const protocol_t *UNUSED(protocol),
				 char *UNUSED(buf), size_t *UNUSED(n))
{
	return -1;
}
