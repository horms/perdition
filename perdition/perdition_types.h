/**********************************************************************
 * perdition_types.h                                     September 1999
 * Horms                                             horms@vergenet.net
 *
 * NB: perdition_tupes.h (this file) and not perdition.h should
 *     be included by other source files
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2001  Horms
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
 *
 **********************************************************************/

#ifndef PERDITION_TYPES_BLUM
#define PERDITION_TYPES_BLUM

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

typedef long int flag_t;

#define NULL_FLAG (flag_t) 0

#define AUTH_RETRY 3
#define PERDITION_ERR_SLEEP 0
#define PERDITION_PROTOCOL_DEPENDANT "protocol dependent"
#define PERDITION_AUTH_FAIL_SLEEP 10
#define PERDITION_CONNECT_RETRY 3

#define PERDITION_USTRING unsigned char *

#define MAX_LINE_LENGTH 4096

#endif
