/**********************************************************************
 * imap4_in.h                                            September 1999
 * Horms                                             horms@verge.net.au
 *
 * Handle IMAP4 commands from a client
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2003  Horms
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

#include <pwd.h>
#include <sys/types.h>
#include <vanessa_adt.h>

#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif

#include "perdition_types.h"
#include "token.h"
#include "imap4_write.h"
#include "log.h"
#include "queue_func.h"

#ifdef WITH_PAM_SUPPORT
#include "pam.h"
#endif


#ifdef WITH_PAM_SUPPORT
/**********************************************************************
 * imap4_in_authenticate
 * Authenticate an incoming pop session
 * Not really needed if we are going to authenticate with an upstream
 * pop server but it may be useful in some cases
 * pre: pw: passwd structure with username and password to authenticate
 *      io: io_t to write errors to
 *      tag: Tag to use in (Error) responses
 * post: An attempt is made to authenticate the user locally
 *       If this fails then an tagged response is written to io
 *       Else no output is made
 * return: 1 if authentication succeeds
 *         0 if authentication fails
 *         -1 if an error occurs
 **********************************************************************/

int imap4_in_authenticate(
  const struct passwd *pw, 
  io_t *io,
  const token_t *tag 
);
#endif /* WITH_PAM_SUPPORT */


/**********************************************************************
 * imap4_in_get_pw
 * read USER and PASS commands and return them in a struct passwd *
 * allocated by this function
 * Pre: io: io_t to read from and write to
 *      return_pw: pointer to an allocated struct pw, 
 *                 where username and password
 *                 will be returned if one is found
 *      return_tag: pointer to return clients tag
 * Post: pw_return structure with pw_name and pw_passwd set
 * Return: 0 on success
 *         1 if user quits (LOGOUT command)
 *         -1 on error
 **********************************************************************/

int imap4_in_get_pw(io_t *io, struct passwd *return_pw, token_t **return_tag);


/**********************************************************************
 * imap4_in_noop_cmd
 * Do a response to a NOOP command
 * pre: io: io_t to write to
 * post: Tagged response to NOOP is written to io
 * return: 0 on success
 *         -1 otherwise
 **********************************************************************/

int imap4_in_noop_cmd(io_t *io, const token_t *tag);


/**********************************************************************
 * imap4_in_logout_cmd
 * Do a response to a LOGOUT command
 * pre: io: io_t to write to
 * post: An untagged response advising of logout is written to io
 *       A tagged response to the LOGOUT is written to io
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

int imap4_in_logout_cmd(io_t *io, const token_t *tag);


/**********************************************************************
 * imap4_in_capability_cmd
 * Do a response to a CAPABILITY command
 * pre: io: io_t to write to
 * post: An untagged response giving capabilities is written to io
 *       A tagged response to the CAPABILITY command is written to io
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

int imap4_in_capability_cmd(io_t *io, const token_t *tag);


/**********************************************************************
 * imap4_in_authenticate_cmd
 * Do a response to an AUTHENTICATE command
 * pre: io: io_t to write to
 * post: A tagged error to the AUTHENTICATE command is given
 * return 0 on success
 *        -1 otherwise
 **********************************************************************/

int imap4_in_authenticate_cmd(io_t *io, const token_t *tag);

#endif
