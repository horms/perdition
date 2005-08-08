/**********************************************************************
 * server_port.c                                               May 1999
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "server_port.h"
#include "options.h"
#include "perdition_globals.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif



/**********************************************************************
 * user_server_port_create
 * Create an empty user_server_port structure
 **********************************************************************/

user_server_port_t *user_server_port_create (void){
       	user_server_port_t *usp;
	
	usp= (user_server_port_t *)calloc(1, sizeof(user_server_port_t));
	if(!usp) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc");
		return(NULL);
	}

	return(usp);
}


/**********************************************************************
 * user_server_port_assign
 * Assign values to a user_server_port_structure
 **********************************************************************/

int
user_server_port_assign(user_server_port_t **usp, char *user, 
		char *server, char *port)
{
	if(!*usp) {
		*usp = user_server_port_create();
		if(!*usp) {
			VANESSA_LOGGER_DEBUG("user_server_port_create");
			return(-1);
		}
	}

	(*usp)->user = user;
	(*usp)->server = server;
	(*usp)->port = port;

	return(0);
}


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
user_server_port_str_assign(user_server_port_t **usp, const char *str)
{
	return user_server_port_strn_assign(usp, str, strlen(str));
}


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
		size_t str_len)
{
	int alloced = 0;

	if(!*usp) {
		*usp = user_server_port_create();
		if(!*usp) {
			VANESSA_LOGGER_DEBUG("user_server_port_create");
			return(-1);
		}
		alloced = 1;
	}
	else {
		user_server_port_unassign(*usp);
	}

	(*usp)->server = (char *) malloc (str_len + 1);
	if(!(*usp)->server) {
		goto strdup_fail;
	}
	memset((*usp)->server, 0, str_len + 1);
	strncpy((*usp)->server, str, str_len);

	(*usp)->port = strrchr((*usp)->server, SERVER_PORT_DELIMITER);
	if((*usp)->port) {
		*(*usp)->port = '\0';
		(*usp)->port++;
		(*usp)->port = strdup((*usp)->port);
		if(!(*usp)->port) {
			goto strdup_fail;
		}
	}

	(*usp)->user = (*usp)->server;
	(*usp)->server = strrstr((*usp)->user, opt.domain_delimiter);
	if((*usp)->server) {
		*(*usp)->server = '\0';
		(*usp)->server += strlen(opt.domain_delimiter);
		(*usp)->server = strdup((*usp)->server);
		if(!(*usp)->server) {
			goto strdup_fail;
		}
	}
	else {
		(*usp)->server = (*usp)->user;
		(*usp)->user = NULL;
	}

	return(0);

strdup_fail:
	VANESSA_LOGGER_DEBUG_ERRNO("strdup");
	str_free((*usp)->user);
	str_free((*usp)->server);
	str_free((*usp)->port);
	if(alloced) {
		free(*usp);
		*usp = NULL;
	}
	return(-1);
}


/**********************************************************************
 * user_server_port_unassign
 * Unassign any values but do not free their memory.
 **********************************************************************/

void 
user_server_port_unassign(user_server_port_t *usp)
{
	memset(usp, 0, sizeof(user_server_port_t));
}


/**********************************************************************
 * user_server_port_destroy
 * Free a user_server_port structure and free any non NULL elements.
 *
 * If you don't want to free the memory  of elements you should
 * use user_server_port_unassign(user_server_port);
 * first.
 **********************************************************************/

void 
user_server_port_destroy(user_server_port_t *usp)
{
      	if(!usp){
		return;
	}

	if(usp->user){
		free(usp->user);
	}
	if(usp->server){
		free(usp->server);
	}
	if(usp->port){
		free(usp->port);
	}

	free(usp);
}

/**********************************************************************
 * user_server_port_destroy_cb
 * Callback version of user_server_port_destroy for use with
 * libvanessa_adt
 **********************************************************************/

void
user_server_port_destroy_cb(void *p)
{
	user_server_port_destroy(p);
}



/**********************************************************************
 * user_server_port_get_port
 * Get the port from a user_server_port structure
 **********************************************************************/

char * 
user_server_port_get_port(const user_server_port_t *usp)
{
  	return(usp->port);
}


/**********************************************************************
 * user_server_port_get_server
 * Get the servername from a user_server_port_structure
 **********************************************************************/

char * 
user_server_port_get_server(const user_server_port_t *usp){
	return(usp->server);
}

/**********************************************************************
 * user_server_port_get_user
 * Get the user from a user_server_port_structure
 **********************************************************************/

char * 
user_server_port_get_user(const user_server_port_t *usp){
	return(usp->user);
}


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
user_server_port_display(char *str, const user_server_port_t *usp)
{
	if(!usp)
		return;
	
	*str = '\0';
	if (usp->user) {
		strcat(str, usp->user);
		strcat(str, opt.domain_delimiter);
	}
	strcat(str, usp->server);
	if (usp->port) {
		*(str + strlen(str) + 1) = '\0';
		*(str + strlen(str)) = SERVER_PORT_DELIMITER;
		strcat(str, usp->port);
	}
}


/**********************************************************************
 * user_server_port_display_cb
 * Render a server port structure to a string with the 
 * Callback version of user_server_port_display for use with 
 * libvanessa_adt
 **********************************************************************/

void
user_server_port_display_cb(char *str, void *p)
{
	user_server_port_display(str, p);
}


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
user_server_port_length(const user_server_port_t *src)
{
	size_t len = 0;

	if(!src){
		return(0);
	}

	len += src->user ? strlen(src->user) + strlen(opt.domain_delimiter) : 0;
	len += src->server ? strlen(src->server) : 0;
	len += src->port ? strlen(src->port) + 1: 0;

    	return(len);
}


/**********************************************************************
 * user_server_port_length_cb
 * Callback version of user_server_port_length for use with 
 * libvanessa_adt
 **********************************************************************/

size_t 
user_server_port_length_cb(void *p)
{
	return user_server_port_length(p);
}


/**********************************************************************
 * user_server_port_dup
 * Duplicate a user_server_port
 * pre: src: user_server_port to duplicate
 * post: src is duplicated
 * return: copy of user_server_port
 *         NULL on error or of src is NULL
 **********************************************************************/

user_server_port_t *
user_server_port_dup(user_server_port_t *src)
{
      	user_server_port_t *dest;

	if(!src) {
		return(NULL);
	}
	
	dest=user_server_port_create();
	if(!dest) {
		return(NULL);
	}

	dest->user=(src->user)?strdup(src->user):NULL;
	dest->server=(src->server)?strdup(src->server):NULL;
	dest->port=(src->port)?strdup(src->port):NULL;

	return(dest);
}


/**********************************************************************
 * user_server_port_dup_cb
 * Callback version of user_server_port_dup for use with 
 * libvanessa_adt
 **********************************************************************/

void *
user_server_port_dup_cb(void *p)
{
	return user_server_port_dup(p);
}

