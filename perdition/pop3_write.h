/**********************************************************************
 * pop3_write.h                                          September 1999
 * Horms                                             horms@vergenet.net
 *
 * Write POP3 protocol commands and responses
 *
 * perdition
 * Mail retreival proxy server
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

#ifndef POP3_WRITE_FLIM
#define POP3_WRITE_FLIM

#include "log.h"
#include "str.h"
#include "token.h"


#define POP3_GREETING "POP3 Ready"
#define POP3_QUIT "QUIT"
#define POP3_OK "+OK"
#define POP3_ERR "-ERR"
#define POP3_DEFAULT_PORT "110"

int pop3_write(
  const int fd, 
  const flag_t flag,
  const token_t *tag,
  const char *type, 
  const char *string
);

#endif

