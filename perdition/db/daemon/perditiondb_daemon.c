/**********************************************************************
 * perditiondb_daemon.c                                       June 2003
 * Horms                                             horms@verge.net.au
 *
 * Access a perdition map daemon database
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif


#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vanessa_logger.h>
#include <vanessa_adt.h>

#include "options.h"
#include "lib/packet.h"
#include "lib/unix_socket.h"

#define DIR_TEMPLATE "/tmp/perdition-map-XXXXXX"
#define SOCK_BASE "map"

#define TIMEOUT 1
#define MAX_RETRY 5

static vanessa_dynamic_array_t *a=NULL;
static char *server_socket = PERDITION_UN_SERVER_SOCKET;
static int timeout = TIMEOUT;
static int max_retry = MAX_RETRY;


/**********************************************************************
 * dbserver_init
 * Parse options string.
 * pre: options_str: Options string. of the form
 *      [server_socket[:timeout[:max_retry]]]
 * post: Options string is parsed if not null
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int 
dbserver_init(char *options_str)
{
	int count;
	char *tmp_str;

	if(options_str==NULL || a!=NULL){
		return(0);
	}

	if((tmp_str=strdup(options_str))==NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("strdup");
		a = NULL;
		return(-1);
	}

	a = vanessa_dynamic_array_split_str(tmp_str,  ':');
	if(!a) {
		VANESSA_LOGGER_DEBUG("vanessa_dynamic_array_split_str");
		a=NULL;
		free(tmp_str);
		return(-1);
	}

	count = vanessa_dynamic_array_get_count(a);
	if(count > 0){ 
		server_socket = vanessa_dynamic_array_get_element(a, 0); 
	}
	if(count > 1){ 
		timeout = atoi(vanessa_dynamic_array_get_element(a, 1)); 
	}
	if(count > 2){ 
		max_retry = atoi(vanessa_dynamic_array_get_element(a, 2)); 
	}

	free(tmp_str);

	return(0);
}



/**********************************************************************
 * dbserver_get2
 * Read the server (value) from a gdbm map given the user (key)
 * pre: key_str: Key as a null terminated string
 *      options_str: Options string. 
 *                   Ignored if NULL
 *                   Used as the map to open otherwise
 *      str_return: value is returned here
 *      len_return: length of value is returned here
 * post: The str_key is looked up in the gdbm map and the
 *       corresponding value is returned in str_return and len_return.
 * return:  0 on success
 *         -1 on file access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int 
dbserver_get2(const char *key_str, const char *options_str,
	      	char **user_return, char **server_return,
		char **port_return)
{
	perdition_un_t sock;
	perdition_un_t peer;
	struct sockaddr_un unaddr;
	int bytes;
	int status = -1;
	int rc;
	perdition_packet_t *packet = NULL;
	char saddr[NI_MAXHOST];
	char sport[NI_MAXSERV];
	char daddr[NI_MAXHOST];
	char dport[NI_MAXSERV];
	perdition_packet_str_t saddr_pstr;
	perdition_packet_str_t sport_pstr;
	perdition_packet_str_t daddr_pstr;
	perdition_packet_str_t dport_pstr;
	perdition_packet_str_t key_pstr;
	perdition_packet_str_t domain_delimiter_pstr;
	perdition_packet_str_t user_pstr;
	perdition_packet_str_t server_pstr;
	perdition_packet_str_t port_pstr;
	struct sockaddr_in *peername_in;
	struct sockaddr_in *sockname_in;

	packet = perdition_packet_create();
	if(!packet) {
		VANESSA_LOGGER_DEBUG("perdition_packet_create");
		goto leave;
	}

	PERDITION_PACKET_STR_PACK(key_pstr, (char *)key_str);
	PERDITION_PACKET_STR_PACK(domain_delimiter_pstr, opt.domain_delimiter);

	if ((peername && peername->ss_family == AF_INET6) ||
	    (sockname && sockname->ss_family == AF_INET6))
	{
		/* IPv6 */
		if (peername) {
			rc = getnameinfo((struct sockaddr *)peername, sizeof(*peername),
					 saddr, NI_MAXHOST, sport, NI_MAXSERV,
					 NI_NUMERICHOST|NI_NUMERICSERV);
			if (rc) {
				VANESSA_LOGGER_DEBUG_UNSAFE("getnameinfo peername: %s",
							    gai_strerror(rc));
				goto leave;
			}
		} else {
			*saddr = '\0';
			*sport = '\0';
		}
		PERDITION_PACKET_STR_PACK(saddr_pstr, saddr);
		PERDITION_PACKET_STR_PACK(sport_pstr, sport);

		if (sockname) {
			rc = getnameinfo((struct sockaddr *)sockname, sizeof(*sockname),
					 daddr, NI_MAXHOST, dport, NI_MAXSERV,
					 NI_NUMERICHOST|NI_NUMERICSERV);
			if (rc) {
				VANESSA_LOGGER_DEBUG_UNSAFE("getnameinfo sockname: %s",
							    gai_strerror(rc));
				goto leave;
			}
		} else {
			*daddr = '\0';
			*dport = '\0';
		}
		PERDITION_PACKET_STR_PACK(daddr_pstr, daddr);
		PERDITION_PACKET_STR_PACK(dport_pstr, dport);

		if(perdition_packet_init_v1_str_req(&packet,
						    PERDITION_PACKET_CS_NONE,
						    &saddr_pstr, &sport_pstr,
						    &daddr_pstr, &dport_pstr,
						    &key_pstr,
						    &domain_delimiter_pstr) < 0) {
			VANESSA_LOGGER_DEBUG("perdition_packet_init_v1_str_req");
			goto leave;
		}
	} else {
		/* IPv4  can also use a str_request, as is used for IPv6,
		 * however the older req format is used for compatibility
		 * with servers that pre-date str_request */

		peername_in = (struct sockaddr_in *) peername;
		sockname_in = (struct sockaddr_in *) sockname;

		if(perdition_packet_init_v1_req(&packet, 0,
				peername_in ? peername_in->sin_addr.s_addr:0UL,
				peername_in ? peername_in->sin_port:0U,
				sockname_in ? sockname_in->sin_addr.s_addr:0UL,
				sockname_in ? sockname_in->sin_port:0U,
				&key_pstr, &domain_delimiter_pstr) < 0) {
			VANESSA_LOGGER_DEBUG("perdition_packet_init_v1");
			goto leave;
		}
	}

	perdition_un_init(&sock);

	memcpy(sock.dir, DIR_TEMPLATE, PERDITION_UN_STR_LEN-1);
	if(!mkdtemp(sock.dir)) {
		VANESSA_LOGGER_DEBUG_ERRNO("mkdtemp");
		return (-1);
	}
	snprintf(sock.name, PERDITION_UN_STR_LEN-1, "%s/%s.%d", 
			sock.dir, SOCK_BASE, getpid());

	sock.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (peer.fd < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("socket");
		goto leave;
	}

	memset(&unaddr, 0, sizeof(struct sockaddr_un));
	unaddr.sun_family = AF_UNIX;
	strncpy(unaddr.sun_path, sock.name, sizeof(struct sockaddr_un));

	if(bind(sock.fd, (struct sockaddr *) &unaddr, 
				sizeof(struct sockaddr_un)) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("bind");
		goto leave;
	}

	perdition_un_init(&peer);
	strncpy(peer.name, server_socket, PERDITION_UN_STR_LEN-1);

	bytes = perdition_un_send_recv(&sock, &peer, (void *)packet, 
			ntohs(packet->head.length),
			PERDITION_PACKET_MAX_PACKET_LEN, timeout, max_retry);
	if(bytes < 0) {
		VANESSA_LOGGER_DEBUG("send_recv_packet");
		goto leave;
	}

	if(perdition_packet_verify_v1_rsp(packet, bytes,
				&user_pstr, &server_pstr, &port_pstr) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_verify_v1_req");
		goto leave;
	}

       	*user_return = (char *)calloc(1, user_pstr.length + 1);
	if(!*user_return) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc user");
		goto leave;
	}
	if(user_pstr.length) {
		memcpy(*user_return, user_pstr.data, user_pstr.length);
	}

       	*server_return = (char *)calloc(1, server_pstr.length + 1);
	if(!*server_return) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc server");
		goto leave;
	}
	if(server_pstr.length) {
		memcpy(*server_return, server_pstr.data, server_pstr.length);
	}

       	*port_return = (char *)calloc(1, port_pstr.length + 1);
	if(!*port_return) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc port");
		goto leave;
	}
	if(port_pstr.length) {
		memcpy(*port_return, port_pstr.data, port_pstr.length);
	}

	status = 0;
leave:
	perdition_packet_destroy(packet);
	perdition_un_close(&sock);
	return status;
}
