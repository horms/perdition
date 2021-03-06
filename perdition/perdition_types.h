/**********************************************************************
 * perdition_types.h                                     September 1999
 * Horms                                             horms@verge.net.au
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

#ifndef _PERDITION_TYPES_H
#define _PERDITION_TYPES_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "int.h"

#include <time.h>

typedef uint32 flag_t;

#define NULL_FLAG (flag_t) 0

#define AUTH_RETRY 3
#define VANESSA_LOGGER_ERR_SLEEP 3
#define PERDITION_PROTOCOL_DEPENDANT "protocol dependent"
#define PERDITION_AUTH_FAIL_SLEEP 3
#define PERDITION_CONNECT_RETRY 3

#define MAX_LINE_LENGTH 4096

#define PERDITION_CLIENT	1
#define PERDITION_SERVER	2

#define PERDITION_LOG_STR_SELF   "SELF:  "
#define PERDITION_LOG_STR_CLIENT "CLIENT:"
#define PERDITION_LOG_STR_REAL   "REAL:  "

typedef struct {
	char log_str[MAX_LINE_LENGTH];
	time_t log_time;
} timed_log_t;

#endif /* _PERDITION_TYPES_H */
