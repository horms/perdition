/**********************************************************************
 * packet.c                                                    May 2003
 * Horms                                             horms@verge.net.au
 *
 * Packets for map queries
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

#include "packet.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <vanessa_logger.h>


static int
perdition_packet_init_v1_head(perdition_packet_t **packet,
		u_int16_t cs_type, u_int16_t flags,
		u_int32_t saddr, u_int16_t sport,
		u_int32_t daddr, u_int16_t dport, size_t body_len);

static int
perdition_packet_verify_v1_head(perdition_packet_t *packet, size_t len);

static int
perdition_packet_verify_v1_tail(perdition_packet_t *packet, size_t body_len);


perdition_packet_t *
perdition_packet_create(void) 
{
	perdition_packet_t *packet;

	packet = (perdition_packet_t *)
				calloc(1, sizeof(perdition_packet_t));
	if(!packet) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc");
		return(NULL);
	}

	return(packet);
}

void
perdition_packet_destroy(perdition_packet_t *packet)
{
	if(!packet) {
		return;
	}
	free(packet);
}


#define PACKET_STR_SET(buf, p_str)                                          \
{                                                                           \
	perdition_packet_str_t str;                                         \
	str.length =  p_str ? htons(p_str->length) : 0;                     \
	memcpy(buf, &(str.length), sizeof(str.length));                     \
	buf += sizeof(str.length);                                          \
	if (str.length) {                                                   \
		memcpy(buf, p_str->data, p_str->length);                    \
		buf += p_str->length;                                       \
	}                                                                   \
}


int
perdition_packet_init_v1_req(perdition_packet_t **packet,
		u_int16_t cs_type, 
		u_int32_t saddr, u_int16_t sport,
		u_int32_t daddr, u_int16_t dport, 
		perdition_packet_str_t *key, 
		perdition_packet_str_t *domain_delimiter) 
{
	char *buf;
	perdition_packet_str_t str;
	size_t body_len;

	body_len = sizeof(str.length) + (key ? key->length : 0) +
		sizeof(str.length) + 
		(domain_delimiter ? domain_delimiter->length : 0);

	if(perdition_packet_init_v1_head(packet, cs_type, PERDITION_PACKET_REQ, 
				saddr, sport, daddr, dport, body_len) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_init_v1_head");
		return(-1);
	}

	buf = (*packet)->body;

	/* Fill in Key */
	PACKET_STR_SET(buf, key);
	/* Fill in Domain Delimiter */
	PACKET_STR_SET(buf, domain_delimiter);

	return(0);
}

int
perdition_packet_init_v1_rsp(perdition_packet_t **packet,
		u_int16_t cs_type, perdition_packet_str_t *user,
		perdition_packet_str_t *server,
		perdition_packet_str_t *port)
{
	char *buf;
	perdition_packet_str_t str;
	size_t body_len;

	body_len = sizeof(str.length) + (user ? user->length : 0) +
		sizeof(str.length) + (server ? server->length : 0) +
		sizeof(str.length) + (port ? port->length : 0);

	if(perdition_packet_init_v1_head(packet, cs_type, PERDITION_PACKET_RSP,
				0, 0, 0, 0, body_len) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_init_v1_head");
		return(-1);
	}
	buf = (*packet)->body;

	/* Fill in User */
	PACKET_STR_SET(buf, user);
	/* Fill in Server */
	PACKET_STR_SET(buf, server);
	/* Fill in Port */
	PACKET_STR_SET(buf, port);

	return(0);
}

static int
perdition_packet_init_v1_head(perdition_packet_t **packet,
		u_int16_t cs_type, u_int16_t flags,
		u_int32_t saddr, u_int16_t sport,
		u_int32_t daddr, u_int16_t dport, size_t body_len)
{
	if (cs_type != PERDITION_PACKET_CS_NONE) {
		VANESSA_LOGGER_DEBUG("Only checksum type none is implemented");
		return(-1);
	}

	if (body_len > PERDITION_PACKET_MAX_BODY_LEN) {
		VANESSA_LOGGER_DEBUG("Strings supplied would overflow body");
		return(-1);
	}

	if (!*packet) {
		*packet = perdition_packet_create();
		if (!*packet) {
			VANESSA_LOGGER_DEBUG("perdition_packet_create");
			return(-1);
		}
	}
	else {
		memset(*packet, 0, sizeof(perdition_packet_t));
	}

	/* Fill in Head */
	(*packet)->head.magic = htonl(PERDITION_PACKET_MAGIC);
	(*packet)->head.version = htons(PERDITION_PACKET_VERSION);
	(*packet)->head.flags = htons(flags);
	(*packet)->head.length = htons(sizeof(perdition_packet_head_t) +
		body_len);
	(*packet)->head.cs_type = htons(cs_type);
	(*packet)->head.saddr = htonl(saddr);
	(*packet)->head.sport = htons(sport);
	(*packet)->head.daddr = htonl(daddr);
	(*packet)->head.dport = htons(dport);

	return(0);
}


#define PACKET_STR_GET(buf, p_str)                                          \
{                                                                           \
	perdition_packet_str_t str;                                         \
	memcpy(&(str.length), buf, sizeof(str.length));                     \
	buf += sizeof(str.length);                                          \
	if (p_str) {                                                        \
		p_str->length = ntohs(str.length);                          \
		if (p_str->length) {                                        \
			p_str->data = buf;                                  \
		}                                                           \
		else {                                                      \
			p_str->data = NULL;                                 \
		}                                                           \
	}                                                                   \
	buf += ntohs(str.length);                                           \
}

int
perdition_packet_verify_v1_req(perdition_packet_t *packet,
		size_t len, perdition_packet_str_t *key,
		perdition_packet_str_t *domain_delimiter) 
{
	char *buf;

	if(perdition_packet_verify_v1_head(packet, len) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_verify_v1_head");
		return(-1);
	}

	if(ntohs(packet->head.flags) != PERDITION_PACKET_REQ) {
		VANESSA_LOGGER_DEBUG("Packet is not a request");
		return(-1);
	}

	buf = packet->body;

	/* Fill in Key */
	PACKET_STR_GET(buf, key);
	/* Fill in Domain Delimiter */
	PACKET_STR_GET(buf, domain_delimiter);

	if(perdition_packet_verify_v1_tail(packet, buf - packet->body) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_verify_v1_head");
		return(-1);
	}

	return(0);
}


int
perdition_packet_verify_v1_rsp(perdition_packet_t *packet,
		size_t len, perdition_packet_str_t *user,
		perdition_packet_str_t *server,
		perdition_packet_str_t *port) 
{
	char *buf;

	if(perdition_packet_verify_v1_head(packet, len) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_verify_v1_head");
		return(-1);
	}

	if(ntohs(packet->head.flags) != PERDITION_PACKET_RSP) {
		VANESSA_LOGGER_DEBUG("Packet is not a response");
		return(-1);
	}

	buf = packet->body;

	/* Fill in Key */
	PACKET_STR_GET(buf, user);
	/* Fill in Server */
	PACKET_STR_GET(buf, server);
	/* Fill in Port */
	PACKET_STR_GET(buf, port);

	if(perdition_packet_verify_v1_tail(packet, buf - packet->body) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_verify_v1_head");
		return(-1);
	}

	return(0);
}


static int
perdition_packet_verify_v1_head(perdition_packet_t *packet, size_t len) 
{
	if (len < sizeof(perdition_packet_head_t)) {
		VANESSA_LOGGER_DEBUG("Packet is too short to contain body");
		return(-1);
	}

	if (packet->head.magic != htonl(PERDITION_PACKET_MAGIC)) {
		VANESSA_LOGGER_DEBUG("Magic number missmatch");
		return(-1);
	}

	if (len > PERDITION_PACKET_MAX_PACKET_LEN) {
		VANESSA_LOGGER_DEBUG("Packet is too long");
		return(-1);
	}

	if (len != ntohs(packet->head.length)) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Packet length missmatch. "
				"Have %d bytes, header specifies %d bytes",
				len, ntohs(packet->head.length));
	}

	if (packet->head.cs_type != PERDITION_PACKET_CS_NONE) {
		VANESSA_LOGGER_DEBUG("Only checksum type none is implemented");
		return(-1);
	}

	return(0);
}

static int
perdition_packet_verify_v1_tail(perdition_packet_t *packet, size_t body_len) 
{
	if (body_len > PERDITION_PACKET_MAX_BODY_LEN) {
		VANESSA_LOGGER_DEBUG("Strings supplied would overflow body");
		return(-1);
	}

	if(body_len + sizeof(packet->head) != ntohs(packet->head.length)) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Length of strings in body does "
				"not match length of packet."
				"strings (%d) + head (%d) != %d",
				body_len, sizeof(packet->head), 
				ntohs(packet->head.length));
		return(-1);
	}

	return(0);
}


