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

#include <pwd.h>
#include <sys/types.h>
#include "token.h"

#define PROTOCOL_OK  0
#define PROTOCOL_ERR 1
#define PROTOCOL_NO  1
#define PROTOCOL_BAD 2

struct protocol_t_struct {
	char **type;
	int (*write)(io_t *io, flag_t flag, const token_t *tag,
			const char *command, size_t nargs, 
			const char *fmt, ...);
	int (*greeting)(io_t *io, flag_t flag);
	char *quit_string;
	int (*in_get_pw) (io_t *io, flag_t ssl_flags, flag_t ssl_state,
			  struct passwd *return_pw, token_t **return_tag);
	int (*out_setup) (io_t *rs_io, io_t *eu_io, const struct passwd *pw,
				 token_t *tag);
	int (*out_authenticate) (io_t *rs_io, io_t *eu_io, 
				 const struct passwd *pw, token_t *tag,
				 const struct protocol_t_struct *protocol,
				 char *buf, size_t *n);
	int (*in_authenticate) (const struct passwd *pw, io_t *io,
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
