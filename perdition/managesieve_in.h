#ifndef PERDITION_MANAGESIEVE_IN_H
#define PERDITION_MANAGESIEVE_IN_H

#include "token.h"
#include "io.h"

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

int managesieve_in_authenticate(const struct passwd *pw, io_t *io,
				const token_t *tag);
#endif /* WITH_PAM_SUPPORT */

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
 *	   1 if user quits (LOGOUT command)
 *	   -1 on error
 **********************************************************************/

int managesieve_in_get_pw(io_t *io, flag_t tls_flags, flag_t tls_state,
			  struct passwd *return_pw, token_t **return_tag);

#endif /* PERDITION_MANAGESIEVE_IN_H */
