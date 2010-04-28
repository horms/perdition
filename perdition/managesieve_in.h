#ifndef PERDITION_MANAGESIEVE_IN_H
#define PERDITION_MANAGESIEVE_IN_H

#include "auth.h"
#include "token.h"
#include "io.h"

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

int managesieve_in_authenticate(const struct auth *auth, io_t *io,
				const token_t *tag);
#endif /* WITH_PAM_SUPPORT */

/**********************************************************************
 * managesieve_in_get_auth
 * allocated by this function
 * pre: io: io_t to write to and read from
 *	tls_flags: the encryption flags that have been set
 *	tls_state: the current state of encryption for the session
 *	return_auth: pointer to an allocated struct auth,
 *		     where login credentials will be returned
 *		     will be returned if one is found
 *	return_tag: ignored
 * post: return_auth is seeded
 * return: 0 on success
 *	   1 if user quits (LOGOUT command)
 *	   2 if TLS negotiation should be done
 *	   -1 on error
 **********************************************************************/

int managesieve_in_get_auth(io_t *io, flag_t tls_flags, flag_t tls_state,
			    struct auth *return_auth, token_t **return_tag);

#endif /* PERDITION_MANAGESIEVE_IN_H */
