/**********************************************************************
 * imap4_write.h                                         September 1999
 * Horms                                             horms@vergenet.net
 *
 * Subroutines to write IMAP4 protocol output
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
 *
 **********************************************************************/

#ifndef IMAP4_WRITE_FLIM
#define IMAP4_WRITE_FLIM

#include "log.h"
#include "str.h"
#include "token.h"


#define IMAP4_GREETING "IMAP4 Ready"
#define IMAP4_QUIT "LOGOUT"
#define IMAP4_OK "OK"
#define IMAP4_BAD "BAD"
#define IMAP4_NO "NO"
#define IMAP4_UNTAGED "*"
#define IMAP4_DEFAULT_PORT "143"
#define IMAP4_ONE_TIME_TAG "flim7"

#ifndef IMAP4_CAPABILITIES
#define IMAP4_CAPABILITIES "IMAP4 IMAP4REV1"
#endif

int imap4_write(
  const int fd, 
  const flag_t flag,
  const token_t *tag, 
  const char *type, 
  const char *string
);

#endif

