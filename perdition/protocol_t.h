/**********************************************************************
 * protocol_t.h                                          September 1999
 * Horms                                             horms@vergenet.net
 *
 * Types for genetic protoclol layer.
 *
 * NB: protocol_t.h (this file) and not protocol.h should
 *     be included by other source files
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

#ifndef PROTOCOL_T_FLIM
#define PROTOCOL_T_FLIM

#include <vanessa_adt.h>

#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif

#include <pwd.h>
#include <sys/types.h>
#include "token.h"

#define PROTOCOL_OK  0
#define PROTOCOL_ERR 1
#define PROTOCOL_NO  1
#define PROTOCOL_BAD 2

struct protocol_t_struct {
  char **type;
  int (*write)(
    const int, 
    const flag_t, 
    const token_t *, 
    const char *, 
    const char *
  );
  char *greeting_string;
  char *quit_string;
  char *one_time_tag;
  int (*in_get_pw)(const int, const int, struct passwd *return_pw, token_t **);
  int (*out_authenticate)(
    const int, 
    const int, 
    const struct passwd *,
    const token_t *tag,
    const struct protocol_t_struct *,
    unsigned char *buf,
    size_t *n
  );
  int (*in_authenticate)(
    const struct passwd *pw,
    const int err_fd,
    const token_t *tag
  );
  int (*out_response)(
    const int, 
    const char *, 
    const token_t *,
    vanessa_queue_t **,
    unsigned char *buf,
    size_t *n
  );
  void (*destroy)(struct protocol_t_struct *);
  char *(*port)(char *);
}; 

typedef struct protocol_t_struct protocol_t;

#endif

