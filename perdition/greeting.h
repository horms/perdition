/**********************************************************************
 * greeting.h                                              October 1999
 * Horms                                             horms@verge.net.au
 *
 * Protocol independent writes
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2004  Horms
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

#ifndef GREETING_BLUM
#define GREETING_BLUM

#include <pwd.h>
#include <sys/types.h>
#include <sys/utsname.h>

#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif

#include "perdition_types.h"
#include "imap4_write.h"
#include "log.h"
#include "protocol_t.h"

/* Flags for greeting() and greeting_str()*/
#define GREETING_ADD_NODENAME (flag_t)0x1    /*Append nodename to message*/


/**********************************************************************
 * greeting
 * Send a greeting to the user
 * pre: io_t: io_t to write to
 *      protocol: Protocol in use
 *      message: Message to display
 *      flag: Flags as per greeting.h
 * post: greeting is written to io
 * return 0 on success
 *        -1 on error
 **********************************************************************/

int greeting(io_t *io, const protocol_t *protocol, flag_t flag);


/**********************************************************************
 * greeting_str
 * Produce greeting string
 * pre: protocol: Protocol in use
 *      flag: Flags as per greeting.h
 * post: Protocol specific message string is formed
 * return message string on success
 *        NULL on error
 **********************************************************************/

char *greeting_str(const protocol_t *protocol, flag_t flag);

#endif
