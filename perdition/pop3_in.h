/**********************************************************************
 * pop3_in.h                                             September 1999
 * Horms                                             horms@vergenet.net
 *
 * Handle pop commands from a client
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
 **********************************************************************/

#ifndef POP3_IN_BLUM
#define POP3_IN_BLUM

#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif

#include <pwd.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <vanessa_adt.h>

#include "token.h"
#include "pop3_write.h"
#include "log.h"
#include "perdition_types.h"
#include "str.h"
#include "queue_func.h"

#ifdef WITH_PAM_SUPPORT
#include "pam.h"

/**********************************************************************
 * pop3_in_authenticate
 * Authenticate an incoming pop session
 * Not really needed if we are going to authenticate with an upstream
 * pop server but it may be useful in some cases
 * pre: pw: passwd struct with username and password to authenticate
 *      io: io_t to write any errors to
 *      tag: ignored
 * post: An attemped is made to authenticate the user locally.
 *       If this fails then an error message is written to io
 *       Else there is no output to io
 * return: 1 if authentication is successful
 *         0 if authentication is unsuccessful
 *         -1 on error
 **********************************************************************/

int pop3_in_authenticate(
  const struct passwd *pw, 
  io_t *io,
  const token_t *tag
);
#endif /* WITH_PAM_SUPPORT */


/**********************************************************************
 * pop3_in_get_pw
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * pre: io: io_t to write to and read from
 *      return_pw: pointer to an allocated struct pw, 
 *                 where username and password
 *                 will be returned if one is found
 *      return_tag: ignored 
 * post: pw_return structure with pw_name and pw_passwd set
 * return: 0 on success
 *         1 if user quits (QUIT command)
 *         -1 on error
 **********************************************************************/

int pop3_in_get_pw(
  io_t *io,
  struct passwd *return_pw,
  token_t **return_tag
);

#endif
