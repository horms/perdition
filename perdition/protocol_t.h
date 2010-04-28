/**********************************************************************
 * protocol_t.h                                          September 1999
 * Horms                                             horms@verge.net.au
 *
 * Types for genetic protocol layer.
 *
 * NB: protocol_t.h (this file) and not protocol.h should
 *     be included by other source files
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

#ifndef PROTOCOL_T_FLIM
#define PROTOCOL_T_FLIM

#include <vanessa_adt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include "auth.h"
#include "token.h"

#define PROTOCOL_OK  0
#define PROTOCOL_ERR 1
#define PROTOCOL_NO  1
#define PROTOCOL_BAD 2

struct protocol_t_struct {
	char **type;
	int (*write_str)(io_t *io, flag_t flag, const token_t *tag,
			 const char *command, const char *str);
	int (*greeting)(io_t *io, flag_t flag);
	char *quit_string;
	int (*bye)(io_t *io, const char *msg);
	int (*in_get_auth) (io_t *io, flag_t ssl_flags, flag_t ssl_state,
			    struct auth *return_auth, token_t **return_tag);
	int (*out_setup) (io_t *rs_io, io_t *eu_io, const struct auth *auth,
				 token_t *tag);
	int (*out_authenticate) (io_t *rs_io, io_t *eu_io, flag_t ssl_state,
				 const struct auth *auth, flag_t sasl_mech,
				 token_t *tag,
				 const struct protocol_t_struct *protocol,
				 char *buf, size_t *n);
	int (*in_authenticate) (const struct auth *auth, io_t *io,
				const token_t * tag);
	int (*out_response) (io_t *rs_io, io_t *eu_io, const token_t *tag, 
			const token_t *desired_token,
			vanessa_queue_t **q, char *buf,
			size_t *n);
	void (*destroy) (struct protocol_t_struct *protcol);
	char *(*port) (char *port);
	flag_t(*encryption) (flag_t ssl_flags);
};

typedef struct protocol_t_struct protocol_t;

#endif
