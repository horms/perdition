#include "io.h"
#include "managesieve.h"
#include "managesieve_in.h"
#include "managesieve_out.h"
#include "managesieve_write.h"
#include "protocol_t.h"
#include "options.h"
#include "unused.h"
#include "perdition_globals.h"
#include "greeting.h"

/**********************************************************************
 * managesieve_greeting_str
 * String for imap greeting
 * pre: flag: Flags as per greeting.h
 *      tls_flags: the encryption flags that have been set
 * return greeting string
 *        NULL on error
 **********************************************************************/

char *managesieve_greeting_str(flag_t flag)
{
	char *capability = NULL;;
	char *tail = NULL;
	char *message = NULL;

	/* The tls_state argument to managesieve_capability() can be
	 * SSL_MODE_EMPTY as the capability before any tls login has
	 * occurred is desired. Its for the greeting, before anything has
	 * happened.
	 */
	capability = managesieve_capability(SSL_MODE_EMPTY, opt.ssl_mode);
	if (!capability) {
		VANESSA_LOGGER_DEBUG("managesieve_capability");
		goto err;
	}

	tail = greeting_str(MANAGESIEVE_GREETING, flag);
	if (!tail) {
		VANESSA_LOGGER_DEBUG("greeting_str");
		goto err;
	}

	message = malloc(strlen(capability) + 2 +
			 strlen(MANAGESIEVE_OK) + 2 +
			 strlen(tail) + 2);
	if (!message) {
		VANESSA_LOGGER_DEBUG_ERRNO("m alloc");
		goto err;
	}

	strcpy(message, capability);
	strcat(message, "\r\n" MANAGESIEVE_OK " \"");
	strcat(message, tail);
	strcat(message, "\"");

err:
	free(capability);
	free(tail);
	return message;
}

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

int managesieve_greeting(io_t *io, flag_t flag)
{
	char *message = NULL;
	int status = -1;

	message = managesieve_greeting_str(flag);
	if (!message) {
		VANESSA_LOGGER_DEBUG("greeting_str");
		return -1;
	}

	if (managesieve_write_raw(io, message) < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_write_raw");
		goto err;
	}

	status = 0;
err:
	free(message);
	return status;
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
 * managesieve_mangle_capability
 * Modify a capability by exchanging delimiters
 * pre: capability: capability string that has been set
 * return: mangled_capability suitable for sending on the wire,
 *         caller should free this memory
 *         NULL on error
 **********************************************************************/

static char *managesieve_mangle_capability(const char *capability)
{
	const char *start;
	const char *end;
	char *mangled_capability;
	size_t n_len;
	int count;

	const char *old_delimiter = MANAGESIEVE_CAPA_DELIMITER;
	const char *new_delimiter = "\r\n";

	const size_t old_delimiter_len = strlen(old_delimiter);
	const size_t new_delimiter_len = strlen(new_delimiter);

	n_len = 0;
	count = 0;
	start = capability;
	while ((start = strstr(start, old_delimiter))) {
		start += old_delimiter_len;
		count++;
	}

	n_len = strlen(capability) - (count * old_delimiter_len) +
		(count * new_delimiter_len);

	mangled_capability = (char *)malloc(n_len + 1);
	if (!mangled_capability) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		return NULL;
	}
	memset(mangled_capability, 0, n_len + 1);

	end = capability;
	while (1) {
		start = end;
		end = strstr(start, old_delimiter);
		if (!end)
			break;
		strncat(mangled_capability, start, end-start);
		strcat(mangled_capability, new_delimiter);
		end += old_delimiter_len;
	}
	strncat(mangled_capability, start, end-start);

	return mangled_capability;
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

char *managesieve_capability(flag_t tls_flags, flag_t tls_state)
{
	flag_t mode;
	char *capability = NULL;
	char *old_capability;

	capability = opt.managesieve_capability;
	if (!strcmp(capability, PERDITION_PROTOCOL_DEPENDANT))
		capability = MANAGESIEVE_DEFAULT_CAPA;

	if ((tls_flags & SSL_MODE_TLS_LISTEN) &&
	    !(tls_state & SSL_MODE_TLS_LISTEN))
		mode = PROTOCOL_C_ADD;
	else
		mode = PROTOCOL_C_DEL;

	capability = protocol_capability(mode, capability,
					MANAGESIEVE_CAPA_STARTTLS,
					MANAGESIEVE_CAPA_DELIMITER);
	if (!capability) {
		VANESSA_LOGGER_DEBUG("protocol_capability");
		return NULL;
	}

	old_capability = capability;
	capability = managesieve_mangle_capability(old_capability);
	free(old_capability);
	if (!capability) {
		VANESSA_LOGGER_DEBUG("managesieve_mangle_capability");
		return NULL;
	}

	return capability;
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
