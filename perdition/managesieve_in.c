#include "token.h"
#include "io.h"
#include "managesieve_in.h"
#include "managesieve_write.h"
#include "queue_func.h"
#include "unused.h"

#include <pwd.h>

#ifdef WITH_PAM_SUPPORT
/**********************************************************************
 * managesieve_in_authenticate
 * Authenticate an incoming session
 * Not really needed if we are going to authenticate with a real-server,
 * but it may be useful in some cases
 * pre: pw: passwd struct with username and password to authenticate
 *	io: io_t to write any errors to
 *	tag: ignored
 * post: An attemped is made to authenticate the user locally.
 *	 If this fails then an error message is written to io
 *	 Else there is no output to io
 * return: 1 if authentication is successful
 *	   0 if authentication is unsuccessful
 *	   -1 on error
 **********************************************************************/

int managesieve_in_authenticate(const struct passwd *UNUSED(pw),
				io_t *UNUSED(io), const token_t *UNUSED(tag))
{
	return -1;
}
#endif /* WITH_PAM_SUPPORT */

/**********************************************************************
 * managesieve_in_get_pw_loop
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * pre: io: io_t to write to and read from
 *      tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 *      return_pw: pointer to an allocated struct pw,
 *                 where username and password
 *                 will be returned if one is found
 * post: pw_return structure with pw_name and pw_passwd set
 * return: 1 pw obtained
 *         0 on MANAGESIEVE_OK
 *         -1 on MANAGESIEVE_NO
 *         -2 on MANAGESIEVE_BYE
 *         -3 on internal error
 **********************************************************************/

static int
managesieve_in_get_pw_loop(io_t *io, flag_t UNUSED(tls_flags),
			   flag_t UNUSED(tls_state),
			   struct passwd *UNUSED(return_pw))
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

	if (managesieve_no(io, NULL, "Unknown command, mate") < 0) {
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
 * managesieve_in_get_pw
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * pre: io: io_t to write to and read from
 *	tls_flags: the encryption flags that have been set
 *	tls_state: the current state of encryption for the session
 *	return_pw: pointer to an allocated struct pw,
 *		   where username and password
 *		   will be returned if one is found
 *	return_tag: ignored
 * post: pw_return structure with pw_name and pw_passwd set
 * return: 0 on success
 *	   1 if user quits (QUIT command)
 *	   -1 on error
 **********************************************************************/

int managesieve_in_get_pw(io_t *io, flag_t tls_flags, flag_t tls_state,
			  struct passwd *return_pw,
			  token_t **UNUSED(return_tag))
{
	int status;

	while (1) {
		status = managesieve_in_get_pw_loop(io, tls_flags,
						    tls_state, return_pw);
		if (status != 0 && status != -1)
			break;
	}

	return status;
}
