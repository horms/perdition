/**********************************************************************
 * greeting.c                                              October 1999
 * Horms                                             horms@verge.net.au
 *
 * Protocol independent greeting
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "greeting.h"
#include "options.h"
#include "perdition_globals.h"
#include "sock.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * greeting
 * Send a greeting to the user
 * pre: io_t: io_t to write to
 *      protocol: Protocol in use
 *      message: Message to display
 *      flag: Flags as per greeting.h
 * post: greeting is written to io
 * return 0 on success
 *        -1 on error
 **********************************************************************/

int greeting(io_t *io, const protocol_t *protocol, flag_t flag){
  char *message=NULL;

  message=greeting_str(protocol, flag);
  if(!message){
    VANESSA_LOGGER_DEBUG("greeting_str");
    return(-1);
  }
  if(protocol->write(io, NULL_FLAG, NULL, protocol->type[PROTOCOL_OK], 
        1, "%s", message)<0){
    VANESSA_LOGGER_DEBUG("protocol->write");
    return(-1);
  }
  free(message);
  return(0);
}


/**********************************************************************
 * greeting_checksum
 * Produce a checksum for greeting string
 * pre: csum: checksum will be returned here
 * post: Checksum of the output of log_options_str() is checksumed
 *       using str_rolling32() and stored in csum.
 * return: 0 on success
 *         -1 on error
 **********************************************************************/

static int greeting_checksum(uint32 *csum)
{
	char **a, **p;

	a = log_options_str();
	if (!a) {
		VANESSA_LOGGER_DEBUG("log_options_str");
		return -1;
	}

	*csum = 0;
	for (p = a; *p; p++)
		*csum += str_rolling32((unsigned char *)*p, strlen(*p));

	log_options_str_free(a);

	return 0;
}

int getnameinfo_try_lookup(struct sockaddr *addr, char *host, size_t hostlen)
{
	int rc = 0;

	if (!opt.no_lookup)
		rc = getnameinfo(addr, perdition_get_salen(addr),
				 host, hostlen, NULL, 0, 0);

	if (rc == EAI_AGAIN)
		/* Try again for a numeric host */
		rc = getnameinfo(addr, perdition_get_salen(addr),
				 host, hostlen, NULL, 0, NI_NUMERICHOST);

	if (rc)
		VANESSA_LOGGER_DEBUG_UNSAFE("getnameinfo sockname: %s",
					    gai_strerror(rc));

	return rc;
}

/**********************************************************************
 * greeting_str
 * Produce greeting string
 * pre: protocol: Protocol in use
 *      flag: Flags as per greeting.h
 * post: Protocol specific message string is formed
 * return message string on success
 *        NULL on error
 **********************************************************************/

char *greeting_str(const protocol_t *protocol, flag_t flag){
  char *message;
  char host[NI_MAXHOST];
  uint32 csum;
  char csum_str[10];
  int rc;

  if(greeting_checksum(&csum) < 0) {
	  VANESSA_LOGGER_DEBUG("greeting_checksum");
	  return(NULL);
  }
  snprintf(csum_str, sizeof(csum_str) - 1, "%08x", csum);
  csum_str[sizeof(csum_str)-1] = '\0';

  if(flag&GREETING_ADD_NODENAME){
    if (!opt.no_bind_banner && sockname) {
      rc = getnameinfo_try_lookup((struct sockaddr *)sockname,
				  host, NI_MAXHOST);
      if (rc) {
        VANESSA_LOGGER_DEBUG("getnameinfo_try_lookup");
        return NULL;
      }
    }
    else{
      strncpy(host, system_uname->nodename, NI_MAXHOST -1);
    }
    if((message=str_cat(5, protocol->greeting_string, " ", host, " ",
				    csum_str))==NULL){
      VANESSA_LOGGER_DEBUG("str_cat");
      return(NULL);
    }
  }
  else{
    if((message=strdup(protocol->greeting_string))==NULL){
      VANESSA_LOGGER_DEBUG("strdup");
      return(NULL);
    }
  }
  return(message);
}
