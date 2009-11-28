/**********************************************************************
 * quit.c                                                  October 1999
 * Horms                                             horms@verge.net.au
 *
 * Protocol independent quit
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

#include "quit.h"
#include "imap4_tag.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif



/**********************************************************************
 * quit
 * Send a quit request to a server
 * Pre: io: io_t to write to
 * Return 0 on success
 *        -1 on error
 **********************************************************************/

int quit(io_t * io, const protocol_t * protocol, token_t * tag)
{
	token_t *t;
	vanessa_queue_t *q;
	int status = -1;

	if(protocol->write(io, NULL_FLAG, tag, 
				protocol->quit_string, 0, "") < 0) {
		VANESSA_LOGGER_DEBUG("protocol->write");
		return (-1);
	}

	/* 
	 * We need to read the response, even though we don't
	 * care about it
	 */

	if ((t = token_create()) == NULL) {
		VANESSA_LOGGER_DEBUG("token_create");
		goto leave;
	}
	token_assign(t, protocol->type[PROTOCOL_OK],
		     strlen(protocol->type[PROTOCOL_OK]), TOKEN_DONT_CARE);

	if ((protocol->out_response(io, NULL, tag, t, &q, NULL, 
					NULL)) < 0) {
		VANESSA_LOGGER_DEBUG("out_response");
		goto leave;
	}

	status = 0;
      leave:
	imap4_tag_inc(tag);
	token_unassign(t);
	token_destroy(&t);
	vanessa_queue_destroy(q);
	return (status);
}
