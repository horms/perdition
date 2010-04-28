#ifndef PERDITION_MANAGESIEVE_H
#define PERDITION_MANAGESIEVE_H

#include "io.h"
#include "protocol_t.h"
#include "perdition_types.h"

/**********************************************************************
 * managesieve_capability_msg
 * String for imap greeting
 * pre: tls_flags: the encryption flags that have been set
 *      tls_state: the current state of encryption for the session
 *      tail: string to append to the message
 * return capabilituy message, should be freed by caller
 *        NULL on error
 **********************************************************************/

char *managesieve_capability_msg(flag_t tls_flags, flag_t tls_state,
				 const char *tail);

/**********************************************************************
 * managesieve_greeting
 * Send a greeting to the user
 * pre: io_t: io_t to write to
 *	flag: Flags as per greeting.h
 *	tls_flags: the encryption flags that have been set
 * post: greeting is written to io
 * return 0 on success
 *	  -1 on error
 **********************************************************************/

int managesieve_greeting(io_t *io, flag_t flag);

/**********************************************************************
 * managesieve_initialise_protocol
 * Initialise the protocol structure for the managesieve protocol
 * pre: protocol: pointer to an allocated protocol structure
 * return: seeded protocol structure
 *	   NULL on error
 **********************************************************************/

protocol_t *managesieve_initialise_protocol(protocol_t *protocol);

/**********************************************************************
 * managesieve_capability
 * Return the capability string to be used.
 * pre: tls_flags: the encryption flags that have been set
 *	tls_state: the current state of encryption for the session
 * return: capability to use, as per protocol_capability with
 *	   managesieve parameters
 *	   NULL on error
 **********************************************************************/

char *managesieve_capability(flag_t tls_flags, flag_t tls_state);

#endif /* PERDITION_MANAGESIEVE_H */
