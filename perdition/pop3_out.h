/**********************************************************************
 * pop3_out.h                                            September 1999
 * Horms                                             horms@vergenet.net
 *
 * Talk POP3 to an upstream server
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

#ifndef POP3_OUT_BLUM
#define POP3_OUT_BLUM

#include <pwd.h>
#include <sys/types.h>
#include <vanessa_adt.h>

#include "token.h"
#include "pop3_write.h"
#include "perdition_types.h"
#include "queue_func.h"
#include "protocol_t.h"
#include "greeting.h"

int pop3_out_authenticate(
  const int in_fd,
  const int out_fd,
  const struct passwd *pw,
  const token_t *tag,
  const protocol_t *protocol,
  unsigned char *buf,
  size_t *n
);

int pop3_out_response(
  int in_fd,
  const char *tag_string,
  const token_t *desired_token,
  vanessa_queue_t **q,
  unsigned char *buf,
  size_t *n
);

#endif
