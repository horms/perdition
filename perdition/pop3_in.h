/**********************************************************************
 * pop3_in.h                                             September 1999
 * Horms                                             horms@vergenet.net
 *
 * Handle pop commands from a client
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
#include "daemon.h"
#include "str.h"
#include "queue_func.h"

#ifdef WITH_PAM_SUPPORT
#include "pam.h"
#endif

int pop3_in_get_pw(
  const int in_fd, 
  const int out_fd, 
  struct passwd *return_pw,
  token_t **tag
);

#ifdef WITH_PAM_SUPPORT
int pop3_in_authenticate(
  const struct passwd *pw,
  const int err_fd,
  const token_t *tag
);
#endif

#endif
