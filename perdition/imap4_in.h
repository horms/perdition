/**********************************************************************
 * imap4_in.h                                            September 1999
 * Horms                                             horms@vergenet.net
 *
 * Handle IMAP4 commands from a client
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
#include "daemon.h"
#include "queue_func.h"

#ifdef WITH_PAM_SUPPORT
#include "pam.h"
#endif


#ifdef WITH_PAM_SUPPORT
int imap4_in_authenticate(
  const struct passwd *pw, 
  const int out_fd,
  const token_t *tag
);
#endif

int imap4_in_get_pw(
  const int in_fd, 
  const int out_fd,
  struct passwd *return_pw,
  token_t **return_tag
);
  
int imap4_in_noop(const int fd, const token_t *tag);

int imap4_in_capability(const int fd, const token_t *tag);

int imap4_in_authenticate_cmd(const int fd, const token_t *tag);

int imap4_in_logout(const int fd, const token_t *tag);
#endif
