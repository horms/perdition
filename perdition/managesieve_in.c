#include "auth.h"
#include "token.h"
#include "io.h"
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

	if (managesieve_ok(io, NULL, NULL) < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_ok");
		goto err;
	}

	status = 0;
err:
	vanessa_queue_destroy(q);
	return status;
}
#endif

/**********************************************************************
 * managesieve_in_get_auth_loop
 * allocated by this function
 * pre: io: io_t to write to and read from
 *      tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 *      return_auth: pointer to an allocated struct auth,
 *                   where login credentials will be returned
 * post: auth_return is seeded
 * return: 3 starttls
 *	   2 logout
 *         1 auth obtained
 *         0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static int
managesieve_in_get_auth_loop(io_t *io, flag_t tls_flags, flag_t tls_state,
			     struct auth *UNUSED(return_auth))
{
	vanessa_queue_t *q = NULL;
	token_t *t = NULL;
	int status = -3;

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

	if (token_casecmp_string(t, MANAGESIEVE_CMD_CAPABILITY)) {
		status = managesieve_in_capability_cmd(io, q,
						       tls_flags, tls_state);
		q = NULL; /* managesieve_in_capability_cmd consumes q */
		if (status < 0)
			goto err;
	} else if (token_casecmp_string(t, MANAGESIEVE_CMD_LOGOUT)) {
		status = managesieve_in_logout_cmd(io, q);
		q = NULL; /* managesieve_in_logout_cmd consumes q */
		if (!status)
			status = 2;
		goto err;
	} else if (token_casecmp_string(t, MANAGESIEVE_CMD_NOOP)) {
		status = managesieve_in_noop_cmd(io, q);
		q = NULL; /* managesieve_in_noop_cmd consumes q */
		if (status < 0)
			goto err;
#ifdef WITH_SSL_SUPPORT
	} else if (tls_flags & SSL_MODE_TLS_LISTEN &&
		   io_get_type(io) != io_type_ssl &&
		   token_casecmp_string(t, MANAGESIEVE_CMD_STARTTLS)) {
		status = managesieve_in_starttls_cmd(io, q);
		q = NULL; /* managesieve_in_starttls_cmd consumes q */
		if (!status)
			status = 3;
		goto err;
#endif
	} else if (managesieve_no(io, NULL, "Unknown command, mate") < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_no");
		status = -1;
		goto err;
	}

	status = 0;
err:
	vanessa_queue_destroy(q);
	token_destroy(&t);
	return status;
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
	int status;

	while (1) {
		status = managesieve_in_get_auth_loop(io, tls_flags,
						      tls_state, return_auth);
		if (status != 0 && status != -1)
			break;
	}

	if (status > 0)
		status--;

	return status;
}
