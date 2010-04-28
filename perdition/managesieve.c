#include "io.h"
#include "managesieve.h"
#include "managesieve_in.h"
#include "managesieve_out.h"
#include "managesieve_write.h"
#include "protocol_t.h"
#include "unused.h"

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

int managesieve_greeting(io_t *UNUSED(io), flag_t UNUSED(flag))
{
	return -1;
}

/**********************************************************************
 * managesieve_destroy_protocol
 * Destroy protocol specific elements of the protocol structure
 **********************************************************************/

static void managesieve_destroy_protocol(protocol_t *UNUSED(protocol))
{
	;
}

/**********************************************************************
 * managesieve_port
 * Return the port to be used
 * pre: port: port that has been set
 * post: MANAGESIEVE_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *	 port otherwise
 **********************************************************************/

static char *managesieve_port(char *port)
{
	if (strcmp(PERDITION_PROTOCOL_DEPENDANT, port))
		return port;

	return MANAGESIEVE_DEFAULT_PORT;
}

/**********************************************************************
 * managesieve_encryption
 * Return the encryption states to be used.
 * pre: ssl_flags: the encryption flags that have been set
 * return: ssl_flags to be used
 **********************************************************************/

static flag_t managesieve_encryption(flag_t ssl_flags)
{
	return ssl_flags;
}

/**********************************************************************
 * managesieve_capability
 * Return the capability string to be used.
 * pre: tls_flags: the encryption flags that have been set
 *	tls_state: the current state of encryption for the session
 * return: capability to use, as per protocol_capability with
 *	   managesieve parameters
 *	   NULL on error
 **********************************************************************/

char *managesieve_capability(flag_t UNUSED(tls_flags), flag_t UNUSED(tls_state))
{
	return NULL;
}

/**********************************************************************
 * managesieve_initialise_protocol
 * Initialise the protocol structure for the managesieve protocol
 * pre: protocol: pointer to an allocated protocol structure
 * return: seeded protocol structure
 *	   NULL on error
 **********************************************************************/

static char *managesieve_type[] = { MANAGESIEVE_OK, MANAGESIEVE_NO,
				    MANAGESIEVE_BYE };

protocol_t *managesieve_initialise_protocol(protocol_t *protocol)
{
	protocol->type = managesieve_type;
	protocol->write_str = managesieve_write_str;
	protocol->greeting = managesieve_greeting;
	protocol->quit_string = MANAGESIEVE_QUIT;
	protocol->in_get_pw = managesieve_in_get_pw;
#ifdef WITH_PAM_SUPPORT
	protocol->in_authenticate = managesieve_in_authenticate;
#else
	protocol->in_authenticate = NULL;
#endif
	protocol->out_setup = managesieve_out_setup;
	protocol->out_authenticate = managesieve_out_authenticate;
	protocol->out_response = managesieve_out_response;
	protocol->destroy = managesieve_destroy_protocol;
	protocol->port = managesieve_port;
	protocol->encryption = managesieve_encryption;

	return protocol;
}
