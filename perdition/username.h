/**********************************************************************
 * username.h                                                 June 2001
 * Horms                                             horms@verge.net.au
 *
 * Perdition, POP3 and IMAP4 proxy daemon
 * Routines to mangle usernames.
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

#ifndef USERNAME_BERT
#define USERNAME_BERT

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/**********************************************************************
 * username_add_domain
 * Append the domain part of the address connected to after
 * the domain delimiter if not already present.
 * pre: username: username to strip domain from
 *      in_addr: Source address of connection
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: if state&opt.add_domain &&
 *           username doesn't contain the domain delimiter
 *         append the domain delimiter and the domain for the reverse
 *         lookup of to_addr
 *       else return username
 * return: domain delimiter and domain added as appropriate
 *         NULL on error
 **********************************************************************/

char *username_add_domain(char *username, struct in_addr *to_addr, int state);


/**********************************************************************
 * username_strip
 * Strip the domain name, all characters after opt.domain_delimiter,
 * from a username if it is permitted for a given state.
 * pre: username: username to strip domain from
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: if state&opt.strip_domain
 *         if state is STATE_GET_SERVER and opt.client_server_specification 
 *           return username
 *         else strip the domain name if it is present
 *       else return username
 * return: username, stripped as appropriate
 *         NULL on error
 **********************************************************************/

char *username_strip(char *username, int state);


/**********************************************************************
 * username_lower_case
 * Strip the domain name, all characters after opt.domain_delimiter,
 * from a username if it is permitted for a given state.
 * pre: username: username to strip domain from
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: if state&opt.strip_domain
 *         if state is STATE_GET_SERVER and opt.client_server_specification 
 *           return username
 *         else strip the domain name if it is present
 *       else return username
 * return: username, stripped as appropriate
 *         NULL on error
 **********************************************************************/

char *username_lower_case(char *username, int state);


/**********************************************************************
 * username_mangle
 * Strip the username as per username_strip() then append a domain
 * as per username_add_domain() then convert the result to lowercase
 * using username_lower_case().
 * pre: username: username to manipulate
 *      to_addr: address to do reverse lookup of for username_add_domain
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: Call username_strip(), then username_add_domain() and
 *       username_lower_case().
 * return: username modified as appropriate
 *         NULL on error
 **********************************************************************/

char *username_mangle(char *username, struct in_addr *to_addr, int state);

#endif /* USERNAME_BERT */
