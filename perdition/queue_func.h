/**********************************************************************
 * queue_func.h                                            October 1999
 * Horms                                             horms@vergenet.net
 *
 * Token to encapsulate a byte string
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999  Horms
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

#ifndef QUEUE_FUNC_FLIM
#define QUEUE_FUNC_FLIM

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <vanessa_adt.h>

#include "log.h"
#include "str.h"
#include "perdition_types.h"
#include "daemon.h"
#include "token.h"

vanessa_queue_t *read_line(const int fd, unsigned char *buf, size_t *n);

char *queue_to_string(vanessa_queue_t *q);

#endif
