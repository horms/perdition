#include "base64.h"
#include "buf.h"
#include "auth.h"
#include "token.h"
#include "io.h"
#include "sasl_plain.h"
#include "managesieve.h"
#include "managesieve_in.h"
#include "managesieve_write.h"
#include "acap_token.h"
#include "queue_func.h"
#include "unused.h"
#include "options.h"

#ifdef WITH_PAM_SUPPORT
/**********************************************************************
 * managesieve_in_authenticate
 * Authenticate an incoming session
 * Not really needed if we are going to authenticate with a real-server,
 * but it may be useful in some cases
 * pre: auth: login credentials
 *	io: io_t to write any errors to
 *	tag: ignored
 * post: An attemped is made to authenticate the user locally.
 *	 If this fails then an error message is written to io
 *	 Else there is no output to io
 * return: 1 if authentication is successful
 *	   0 if authentication is unsuccessful
 *	   -1 on error
 **********************************************************************/

int managesieve_in_authenticate(const struct auth *UNUSED(auth),
				io_t *UNUSED(io), const token_t *UNUSED(tag))
{
	return -1;
}
#endif /* WITH_PAM_SUPPORT */

struct managesieve_in_auth_status {
	struct auth auth;
	int status;
};

#define STRUCT_MANAGESIEVE_IN_AUTH_STATUS(name) \
	struct managesieve_in_auth_status (name) = { .status = -3 }

/**********************************************************************
 * managesieve_in_sasl_plain
 * Handle a NOOP command
 * pre: io: io_t to write to and read from
 *      q: queue of tokens read from client.
 * post: q is destroyed
 * return: .auth: seeded auth structure
 *         .status: 0 on MANAGESIEVE_OK (password structure is filled in)
 *                  -1 on MANAGESIEVE_NO
 *                  -2 on MANAGESIEVE_BYE
 *                  -3 on internal error
 **********************************************************************/

static struct managesieve_in_auth_status
managesieve_in_sasl_plain(io_t *io, vanessa_queue_t *q)
{
	STRUCT_AUTH_STATUS(as);
	STRUCT_MANAGESIEVE_IN_AUTH_STATUS(auth_status);
	STRUCT_ACAP_TOKEN_WRAPPER_STATUS(wrapper_status);

	if (vanessa_queue_length(q) != 1) {
		if (managesieve_no(io, NULL, "Incorrect argument count, "
			     "expected AUTHENTICATE \"PLAIN\" <challenge>, "
			     "mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		auth_status.status = -1;
		goto err;
	}

	wrapper_status = acap_token_wrapper(io, PERDITION_CLIENT, q);
	vanessa_queue_destroy(wrapper_status.q);
	q = NULL; /* acap_token_wrapper() consumes q */

	if (wrapper_status.status == -2) {
		VANESSA_LOGGER_DEBUG("acap_token_wrapper");
		goto err;
	}
	if (wrapper_status.status ||
	    !acap_token_wrapper_status_is_eol(&wrapper_status) ||
	    wrapper_status.type == acap_atom) {
		if (managesieve_no(io, NULL, "Invalid AUTHENTICATE \"PLAIN\" "
			     "challenge, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		auth_status.status = -1;
		goto err;
	}

	as = sasl_plain_challenge_decode(wrapper_status.str);
	switch (as.status) {
	case auth_status_ok:
		break;
	case auth_status_invalid:
		if (managesieve_no(io, NULL, as.reason) < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
	case auth_status_error:
		auth_status.status = -1;
		goto err;
	}

	auth_status.auth = as.auth;
	auth_status.status = 0;
err:
	free(wrapper_status.str);
	vanessa_queue_destroy(q);
	return auth_status;
}

/**********************************************************************
 * managesieve_in_authenticate_cmd
 * Handle a NOOP command
 * pre: io: io_t to write to and read from
 *      q: queue of tokens read from client.
 * post: q is destroyed
 * return: .auth: seeded auth structure
 *         .status: 0 on MANAGESIEVE_OK (password structure is filled in)
 *                  -1 on MANAGESIEVE_NO
 *                  -2 on MANAGESIEVE_BYE
 *                  -3 on internal error
 **********************************************************************/

static struct managesieve_in_auth_status
managesieve_in_authenticate_cmd(io_t *io, vanessa_queue_t *q)
{
	token_t *t = NULL;
	STRUCT_MANAGESIEVE_IN_AUTH_STATUS(auth_status);

	if (vanessa_queue_length(q) == 0 || vanessa_queue_length(q) > 2) {
		if (managesieve_no(io, NULL, "Incorrect argument count, "
			     "expected AUTHENTICATE <mechanism> [<challenge>], "
			     "mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		auth_status.status = -1;
		goto err;
	}

	q = vanessa_queue_pop(q, (void **)&t);
	if (!q) {
		VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
		goto err;
	}

	if (token_casecmp_string(t, "\"" SASL_MECHANISM_PLAIN "\"")) {
		auth_status = managesieve_in_sasl_plain(io, q);
		q = NULL; /* managesieve_in_sasl_plain consumes q */
		if (!auth_status.status)
			auth_status.status = 1;
		goto err;
	} else {
		if (managesieve_no(io, NULL,
				   "Unknown SASL mechanism, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		auth_status.status = -1;
		goto err;
	}

	auth_status.status = 0;
err:
	vanessa_queue_destroy(q);
	token_destroy(&t);
	return auth_status;
}

/**********************************************************************
 * managesieve_in_capability_cmd
 * Handle a CAPABILITY command
 * pre: io: io_t to write to and read from
 *      q: queue of tokens read from client.
 *      tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 * post: q is destroyed
 * return: 0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static int managesieve_in_capability_cmd(io_t *io, vanessa_queue_t *q,
					 flag_t tls_flags, flag_t tls_state)
{
	int status = -3;
	char *msg = NULL;

	if (vanessa_queue_length(q) != 0) {
		if (managesieve_no(io, NULL, "Too many arguments, "
			     "expected CAPABILITY, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		status = -1;
		goto err;
	}

	msg = managesieve_capability_msg(tls_flags, tls_state,
				   "CAPABILITY completed, mate");
	if (!msg) {
		VANESSA_LOGGER_DEBUG("managesieve_capability_msg");
		goto err;
	}

	if (managesieve_write_raw(io, msg) < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_write_raw");
		goto err;
	}

	status = 0;
err:
	vanessa_queue_destroy(q);
	free(msg);
	return status;
}

/**********************************************************************
 * managesieve_in_logout_cmd
 * Handle a LOGOUT command
 * pre: io: io_t to write to and read from
 *      q: queue of tokens read from client.
 * post: q is destroyed
 * return: 0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static int managesieve_in_logout_cmd(io_t *io, vanessa_queue_t *q)
{
	int status = -3;

	if (vanessa_queue_length(q) == 0) {
		if (managesieve_ok(io, NULL, "LOGOUT completed, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_ok");
			goto err;
		}
	} else {
		if (managesieve_no(io, NULL, "Too many arguments, "
				   "expected LOGOUT, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		status = -1;
		goto err;
	}

	status = 0;
err:
	vanessa_queue_destroy(q);
	return status;
}

/**********************************************************************
 * managesieve_in_noop_cmd_str
 * Handle the string argument of a NOOP command
 * pre: io: io_t to write to and read from
 *      q: queue of tokens read from client.
 * post: q is destroyed
 * return: 0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static int managesieve_in_noop_cmd_str(io_t *io, vanessa_queue_t *q)
{
	int status = -3;
	token_t *t = NULL;
	char *rc_arg[2];
	STRUCT_MANAGESIEVE_RESPONSE_CODE(rc);
	STRUCT_ACAP_TOKEN_WRAPPER_STATUS(wrapper_status);

	wrapper_status = acap_token_wrapper(io, PERDITION_CLIENT, q);
	vanessa_queue_destroy(wrapper_status.q);
	q = NULL; /* acap_token_wrapper() consumes q */

	if (wrapper_status.status == -2) {
		VANESSA_LOGGER_DEBUG("acap_token_wrapper");
		goto err;
	}
	if (wrapper_status.status ||
	    !acap_token_wrapper_status_is_eol(&wrapper_status) ||
	    wrapper_status.type == acap_atom) {
		if (managesieve_no(io, NULL, "Invalid AUTHENTICATE PLAIN "
				   "challenge, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		status = -1;
		goto err;
	}

	rc_arg[0] = wrapper_status.str;
	rc_arg[1] = NULL;
	rc.atom = "TAG";
	rc.arg = rc_arg;
	if (managesieve_ok(io, &rc, "NOOP completed, mate") < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_no");
		goto err;
	}

	status = 0;
err:
	vanessa_queue_destroy(q);
	token_destroy(&t);
	free(wrapper_status.str);
	return status;
}

/**********************************************************************
 * managesieve_in_noop_cmd
 * Handle a NOOP command
 * pre: io: io_t to write to and read from
 *      q: queue of tokens read from client.
 * post: q is destroyed
 * return: 0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static int managesieve_in_noop_cmd(io_t *io, vanessa_queue_t *q)
{
	int status = -3;

	if (vanessa_queue_length(q) == 0) {
		if (managesieve_ok(io, NULL, "NOOP completed, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_ok");
			goto err;
		}
	} else if (vanessa_queue_length(q) == 1) {
		status = managesieve_in_noop_cmd_str(io, q);
		q = NULL; /* managesieve_in_noop_cmd_str consumes q */
		if (status < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_in_noop_cmd_str");
			goto err;
		}
	} else {
		if (managesieve_no(io, NULL,
				   "Too many arguments, expected NOOP "
				   "[String], mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		status = -1;
		goto err;
	}

	status = 0;
err:
	vanessa_queue_destroy(q);
	return status;
}

#ifdef WITH_SSL_SUPPORT
/**********************************************************************
 * managesieve_in_starttls_cmd
 * Handle a STARTTLS command
 * pre: io: io_t to write to and read from
 *      q: queue of tokens read from client.
 * post: q is destroyed
 * return: 0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static int managesieve_in_starttls_cmd(io_t *io, vanessa_queue_t *q)
{
	int status = -3;

	if (vanessa_queue_length(q) != 0) {
		if (managesieve_no(io, NULL, "Too many arguments, "
			     "expected STARTTLS, mate") < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_no");
			goto err;
		}
		status = -1;
		goto err;
	}

	if (managesieve_ok(io, NULL, "Begin TLS negotiation, mate") < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_ok");
		goto err;
	}

	status = 0;
err:
	vanessa_queue_destroy(q);
	return status;
}

static int managesieve_starttls_post(io_t *io, int tls_flags, int tls_state)
{
	char *msg;
	int status = -1;

	if (!(tls_state & SSL_MODE_TLS_LISTEN))
		return 0;

	msg = managesieve_capability_msg(tls_flags, tls_state,
				   "TLS negotiation completed, mate");
	if (!msg) {
		VANESSA_LOGGER_DEBUG("managesieve_capability_msg");
		goto err;
	}

	if (managesieve_write_raw(io, msg) < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_write_raw");
		goto err;
	}

	status = 0;
err:
	free(msg);
	return status;
}
#else
static int managesieve_starttls_post(io_t *UNUSED(io), int UNUSED(tls_flags),
				     int UNUSED(tls_state))
{
	return 0;
}
#endif

/**********************************************************************
 * managesieve_in_get_auth_loop
 * allocated by this function
 * pre: io: io_t to write to and read from
 *      tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 * post: auth_return is seeded
 * return: 3 starttls
 *	   2 logout
 *         1 auth obtained
 *         0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static struct managesieve_in_auth_status
managesieve_in_get_auth_loop(io_t *io, flag_t tls_flags, flag_t tls_state)
{
	vanessa_queue_t *q = NULL;
	token_t *t = NULL;
	STRUCT_MANAGESIEVE_IN_AUTH_STATUS(as);

	q = read_line(io, NULL, NULL, TOKEN_MANAGESIEVE, 0,
		     PERDITION_LOG_STR_CLIENT);
	if (!q) {
		VANESSA_LOGGER_DEBUG("read_line");
		goto err;;
	}

	q = vanessa_queue_pop(q, (void **)&t);
	if (!q) {
		VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
		goto err;
	}

	if (token_casecmp_string(t, MANAGESIEVE_CMD_AUTHENTICATE)) {
		as = managesieve_in_authenticate_cmd(io, q);
		q = NULL; /* managesieve_in_logout_cmd consumes q */
		if (!as.status)
			as.status = 1;
		goto err;
	} else if (token_casecmp_string(t, MANAGESIEVE_CMD_CAPABILITY)) {
		as.status = managesieve_in_capability_cmd(io, q, tls_flags,
							  tls_state);
		q = NULL; /* managesieve_in_capability_cmd consumes q */
		if (as.status < 0)
			goto err;
	} else if (token_casecmp_string(t, MANAGESIEVE_CMD_LOGOUT)) {
		as.status = managesieve_in_logout_cmd(io, q);
		q = NULL; /* managesieve_in_logout_cmd consumes q */
		if (!as.status)
			as.status = 2;
		goto err;
	} else if (token_casecmp_string(t, MANAGESIEVE_CMD_NOOP)) {
		as.status = managesieve_in_noop_cmd(io, q);
		q = NULL; /* managesieve_in_noop_cmd consumes q */
		if (as.status < 0)
			goto err;
#ifdef WITH_SSL_SUPPORT
	} else if (tls_flags & SSL_MODE_TLS_LISTEN &&
		   io_get_type(io) != io_type_ssl &&
		   token_casecmp_string(t, MANAGESIEVE_CMD_STARTTLS)) {
		as.status = managesieve_in_starttls_cmd(io, q);
		q = NULL; /* managesieve_in_starttls_cmd consumes q */
		if (!as.status)
			as.status = 3;
		goto err;
#endif
	} else if (managesieve_no(io, NULL, "Unknown command, mate") < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_no");
		as.status = -1;
		goto err;
	}

	as.status = 0;
err:
	vanessa_queue_destroy(q);
	token_destroy(&t);
	return as;
}

/**********************************************************************
 * managesieve_in_get_auth
 * allocated by this function
 * pre: io: io_t to write to and read from
 *	tls_flags: the encryption flags that have been set
 *	tls_state: the current state of encryption for the session
 *	return_auth: pointer to an allocated struct auth,
 *		     where login credentials will be returned
 *	return_tag: ignored
 * post: auth_return is seeded
 * return: 0 on success
 *	   1 if user quits (LOGOUT command)
 *	   2 if TLS negotiation should be done
 *	   -1 on error
 **********************************************************************/

int managesieve_in_get_auth(io_t *io, flag_t tls_flags, flag_t tls_state,
			    struct auth *return_auth,
			    token_t **UNUSED(return_tag))
{
	struct managesieve_in_auth_status as;

	if (managesieve_starttls_post(io, tls_flags, tls_state) < 0)
	{
		VANESSA_LOGGER_DEBUG("managesieve_starttls_post");
		return -1;
	}

	while (1) {
		as = managesieve_in_get_auth_loop(io, tls_flags, tls_state);
		if (as.status != 0 && as.status != -1)
			break;
	}

	if (as.status > 0)
		as.status--;
	if (!as.status)
		*return_auth = as.auth;

	return as.status;
}
