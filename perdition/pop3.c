/**********************************************************************
 * pop3.c                                                September 1999
 * Horms                                             horms@verge.net.au
 *
 * POP3 protocol defines
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2003  Horms
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pop3.h"
#include "pop3_in.h"
#include "pop3_out.h"
#include "pop3_write.h"
#include "options.h"
#include "protocol.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif



static void pop3_destroy_protocol(protocol_t *protocol);
static char *pop3_port(char *port);
static flag_t pop3_encryption(flag_t ssl_flags);

/**********************************************************************
 * pop3_intitialise_protocol
 * Intialialoise the protocol structure for the pop3 protocol
 * Pre: protocol: pointer to an allocated protocol structure
 * Post: Return seeded protocol stricture
 *              NULL on error
 **********************************************************************/

char *pop3_type[]={POP3_OK, POP3_ERR, POP3_ERR};

protocol_t *pop3_initialise_protocol(protocol_t *protocol){
  extern char *pop3_type[];

  protocol->type = pop3_type;
  protocol->write = pop3_write;
  protocol->greeting_string = POP3_GREETING;
  protocol->quit_string = POP3_QUIT;
  protocol->in_get_pw= pop3_in_get_pw;
#ifdef WITH_PAM_SUPPORT
  protocol->in_authenticate= pop3_in_authenticate;
#else
  protocol->in_authenticate= NULL;
#endif
  protocol->out_setup = pop3_out_setup;
  protocol->out_authenticate = pop3_out_authenticate;
  protocol->out_response= pop3_out_response;
  protocol->destroy = pop3_destroy_protocol;
  protocol->port = pop3_port;
  protocol->encryption = pop3_encryption;
  protocol->capability = pop3_capability;

  return(protocol);
}


/**********************************************************************
 * pop3_destroy_proto 
 * Destory protocol specifig elements of the protocol struture
 **********************************************************************/

static void pop3_destroy_protocol(protocol_t *protocol)
{
  ;
}


/**********************************************************************
 * pop3_port 
 * Return the port to be used
 * pre: port: port that has been set
 * post: POP3_DEFAULT_PORT if port is PERDITION_PROTOCOL_DEPENDANT
 *       port otherwise
 **********************************************************************/

static char *pop3_port(char *port)
{
  if(!strcmp(PERDITION_PROTOCOL_DEPENDANT, port)){
    return(POP3_DEFAULT_PORT);
  }

  return(port);
}


/**********************************************************************
 * pop3_encryption 
 * Return the encription states to be used.
 * pre: ssl_flags: the encryption flags that bave been set
 * post: return ssl_flags (does nothing)
 **********************************************************************/

static flag_t pop3_encryption(flag_t ssl_flags) 
{
  return(ssl_flags);
}


/**********************************************************************
 * pop3_capability 
 * Return the capability string to be used.
 * pre: capability: capability string that has been set
 *      tls_flags: not used
 *      tls_state: not used
 * post: capability to use, as per protocol_capability
 *       with POP parameters
 **********************************************************************/

/* Be careful with this macro, it does not do bounds checking */
#define __POP3_CAPABILITY_APPEND(_cursor, _capa, _capa_len)           \
	strcpy(_cursor, "S: ");                                       \
	cursor += 3;                                                  \
	strcpy(_cursor, _capa);                                       \
	cursor += _capa_len;                                          \
	strcpy(_cursor, "\r\n");                                      \
	cursor += 2;

char *pop3_capability(char *capability, char **mangled_capability, 
		flag_t tls_flags, flag_t tls_state) 
{
	char *start;
	char *end;
	char *cursor;
	size_t n_len;
	size_t d_len;
	int finish;
	flag_t mode;

	if((tls_flags & SSL_MODE_TLS_OUTGOING) &&
			!(tls_state & SSL_MODE_TLS_OUTGOING)) {
		mode = PROTOCOL_C_ADD;
	}
	else {
		mode = PROTOCOL_C_DEL;
	}
	capability = protocol_capability(capability, PROTOCOL_C_ADD,
			IMAP4_DEFAULT_CAPABILITY, POP3_CMD_STLS,
			IMAP4_CAPABILITY_DELIMITER);
	if(capability == NULL) {
		VANESSA_LOGGER_DEBUG("protocol_capability");
		return(NULL);
	}

      	if(mangled_capability == NULL) {
		return(capability);
	}

	n_len = 0;
	d_len = strlen(POP3_CAPABILITY_DELIMITER);
	end = capability;
	finish = 0;
	while(1) {
		start = end;
		end = strstr(start, POP3_CAPABILITY_DELIMITER);
		if(end == NULL) {
			end = start + strlen(start);
			finish = 1;
		}
		if(!strncmp(start, POP3_CAPABILITY_DELIMITER, d_len)) {
			end += d_len;
			continue;
		}
		n_len += 5  /* Space for leading "S: " and trailing "\r\n"*/
			+  end - start;
		if(finish) {
			break;
		}
		end += d_len;
	}

	n_len += 7; /* Space for trailing "S: .\r\n\0" */
	*mangled_capability = (char *)malloc(n_len + 1);
	if(*mangled_capability == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		free(capability);
		return(NULL);
	}
	memset(*mangled_capability, 0, n_len +1);


	finish = 0;
	end = capability;
	cursor = *mangled_capability;
	while(1) {
		start = end;
		end = strstr(start, POP3_CAPABILITY_DELIMITER);
		if(end == NULL) {
			end = start + strlen(start);
			finish = 1;
		}
		if(end == start && *end != '\0') {
			end += d_len;
			continue;
		}
		if(!strncmp(start, POP3_CAPABILITY_DELIMITER, d_len)) {
			end += d_len;
			continue;
		}
		if(*start == '\0') {
			break;
		}
		__POP3_CAPABILITY_APPEND(cursor, start, end-start);
		if(finish) {
			break;
		}
		end += d_len;
	}
	__POP3_CAPABILITY_APPEND(cursor, ".", 1);
	
	return(capability);
}
