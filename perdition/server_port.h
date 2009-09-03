/**********************************************************************
 * server_port.h                                               May 1999
 * Horms                                             horms@verge.net.au
 *
 * Data type for handling server/port pairs
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/

#ifndef SERVER_PORT_STIX
#define SERVER_PORT_STIX

#include <stdlib.h>
#include "log.h"
#include "str.h"

#define SERVER_PORT_DELIMITER ':'

/* #defines to destroy and duplicate strings */
#define DESTROY_SP   user_server_port_destroy_cb
#define DUPLICATE_SP user_server_port_dup_cb
#define DISPLAY_SP   user_server_port_display_cb
#define LENGTH_SP    user_server_port_length_cb


typedef struct {
  char *user;
  char *server;
  char *port;
} user_server_port_t;

/**********************************************************************
 * user_server_port_create
 * Create an empty user_server_port structure
 **********************************************************************/

user_server_port_t *user_server_port_create (void);


/**********************************************************************
 * user_server_port_assign
 * Assign values to a user_server_port_structure
 **********************************************************************/

int
user_server_port_assign(user_server_port_t **usp, char *user, 
		char *server, char *port);


/**********************************************************************
 * user_server_port_str_assign
 * Assign the data in a string, to a port structure
 * pre: str: string of the form
 *        [<user><domain_delimiter>]<servername>[:<port>]
 * post: <server> is assigned to usp.server
 *       <port> is assigned to usp.port if present, otherwise null
 *       <user> is assigned to usp.user if present, otherwise null
 * return: 0 on success
 *         -1 on error
 **********************************************************************/

int
user_server_port_str_assign(user_server_port_t **usp, const char *str);


/**********************************************************************
 * user_server_port_strn_assign
 * Assign the data in a string, to a port structure
 * pre: str: string of the form
 *        [<user><domain_delimiter>]<servername>[:<port>]
 *      str_len: maximum number of bytes of str to use,
 *               not including traling '\0', if any
 * post: <server> is assigned to usp.server
 *       <port> is assigned to usp.port if present, otherwise null
 *       <user> is assigned to usp.user if present, otherwise null
 * return: 0 on success
 *         -1 on error
 **********************************************************************/

int
user_server_port_strn_assign(user_server_port_t **usp, const char *str,
		size_t str_len);


/**********************************************************************
 * user_server_port_unassign
 * Unassign any values but do not free their memory.
 **********************************************************************/

void 
user_server_port_unassign(user_server_port_t *usp);


/**********************************************************************
 * user_server_port_destroy
 * Free a user_server_port structure and free any non NULL elements.
 *
 * If you don't want to free the memory  of elements you should
 * use user_server_port_unassign(user_server_port);
 * first.
 **********************************************************************/

void 
user_server_port_destroy(user_server_port_t *usp);


/**********************************************************************
 * user_server_port_destroy_cb
 * Callback version of user_server_port_destroy for use with
 * libvanessa_adt
 **********************************************************************/

void 
user_server_port_destroy_cb(void *p);


/**********************************************************************
 * user_server_port_get_port
 * Get the port from a user_server_port structure
 **********************************************************************/

char * 
user_server_port_get_port(const user_server_port_t *usp);


/**********************************************************************
 * user_server_port_get_server
 * Get the servername from a user_server_port_structure
 **********************************************************************/

char * 
user_server_port_get_server(const user_server_port_t *usp);


/**********************************************************************
 * user_server_port_get_user
 * Get the user from a user_server_port_structure
 **********************************************************************/

char * 
user_server_port_get_user(const user_server_port_t *usp);


/**********************************************************************
 * user_server_port_display
 * Render a server port structure to a string with the 
 * server and port separated by SERVER_PORT_DELIMITER
 * Analogous to strcpy for strings
 * pre: dest: allocated string to render user_server_port to
 *      user_server_port: user_server_port_t to render
 * post: user_server_port is rendered to dest with a terminating '\0'
 *       nothing if user_server_port is NULL
 **********************************************************************/

void
user_server_port_display(char *str, const user_server_port_t *usp);


/**********************************************************************
 * user_server_port_display_cb
 * Callback version of user_server_port_display for use with 
 * libvanessa_adt
 **********************************************************************/

void
user_server_port_display_cb(char *str, void *p);


/**********************************************************************
 * user_server_port_length
 * Report the rendered length of a user_server_port not including
 * the trailing '\0'
 * Analogous to strlen for strings
 * pre: src: the server port to find the rendered length of
 * return: rendered length of the user_server_port
 *         0 if user_server_port is NULL
 **********************************************************************/

size_t 
user_server_port_length(const user_server_port_t *src);


/**********************************************************************
 * user_server_port_length_cb
 * Callback version of user_server_port_length for use with 
 * libvanessa_adt
 **********************************************************************/

size_t
user_server_port_length_cb(void *p);


/**********************************************************************
 * user_server_port_dup
 * Duplicate a user_server_port
 * pre: src: user_server_port to duplicate
 * post: src is duplicated
 * return: copy of user_server_port
 *         NULL on error or of src is NULL
 **********************************************************************/

user_server_port_t *
user_server_port_dup(user_server_port_t *src);

/**********************************************************************
 * user_server_port_dup_cb
 * Callback version of user_server_port_dup for use with 
 * libvanessa_adt
 **********************************************************************/

void *
user_server_port_dup_cb(void *p);


#endif /* SERVER_PORT_STIX */
