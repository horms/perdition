/**********************************************************************
 * imap4_write.h                                         September 1999
 * Horms                                             horms@vergenet.net
 *
 * Subroutines to write IMAP4 protocol output
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2002  Horms
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
#define IMAP4_CONT_TAG "+"
#define IMAP4_DEFAULT_PORT "143"
/* #define IMAP4_DEFAULT_CAPABILITY "IMAP4 IMAP4REV1 LITERAL+" */
#define IMAP4_DEFAULT_CAPABILITY "IMAP4 IMAP4REV1"
#define IMAP4_TLS_CAPABILITY "STARTTLS"
#define IMAP4_CAPABILITY_DELIMITER " "
#define IMAP4S_DEFAULT_PORT "993"
#define IMAP4_ONE_TIME_TAG "flim7"

/**********************************************************************
 * imap4_write
 * Display an message of the form [<tag> <type> ]<string>
 * Pre: io: io_t to write to
 *      flag: flag to pass to str_write as per str.h
 *      tag: tag to display
 *           if NULL, then IMAP4_UNTAGED is used
 *      type: type of message, IMAP4_OK, IMAP4_NO or IMAP4_BAD
 *            if NULL then only string is written, no tag and no type
 *      string: mesage to display
 * Return 0 on success
 *        -1 otherwise
 **********************************************************************/

int imap4_write(
  io_t *io,
  const flag_t flag,
  const token_t *tag, 
  const char *type, 
  const char *string
);

#endif

