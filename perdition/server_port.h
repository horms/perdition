/**********************************************************************
 * server_port.h                                               May 1999
 * Horms                                             horms@vergenet.net
 *
 * Data type for handling server/port pairs
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

#ifndef SERVER_PORT_STIX
#define SERVER_PORT_STIX

#include <stdlib.h>
#include "log.h"
#include "str.h"

#define SERVER_PORT_DELIMITER ':'

/* #defines to destroy and dupilcate strings */
#define DESTROY_SP (void (*)(void *s))server_port_destroy
#define DUPLICATE_SP (void *(*)(void *s))server_port_dup
#define DISPLAY_SP (void (*)(char *d, void *s))server_port_display
#define LENGTH_SP (size_t (*)(void *s))server_port_length


typedef struct {
  char *servername;
  char *port;
} server_port_t;

server_port_t *server_port_create (void);
void server_port_assign(
  server_port_t *server_port, 
  char *servername, 
  char *port
);
void server_port_unassign(server_port_t *server_port);
void server_port_destroy(server_port_t *server_port);
char * server_port_get_port(const server_port_t *server_port);
char * server_port_get_servername(const server_port_t *server_port);
server_port_t *server_port_strn_assign(
  server_port_t *server_port,
  const char *str,
  const int len
);
void server_port_display(char *dest, const server_port_t *server_port);
size_t server_port_length(server_port_t *src);
server_port_t *server_port_dup(server_port_t *src);


#endif





