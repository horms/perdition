/**********************************************************************
 * packet.h                                                    May 2003
 * Horms                                             horms@verge.net.au
 *
 * Packets for map queries
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

#ifndef PERDITION_PACKET_H
#define PERDITION_PACKET_H

#include "perdition_globals.h"

#include <sys/types.h>
#include <inttypes.h>
#include <string.h>

#define PERDITION_SOCKET 

#define PERDITION_PACKET_MAGIC   0x07070707
#define PERDITION_PACKET_VERSION 0x00000001

#define PERDITION_PACKET_REQ     0x0001
#define PERDITION_PACKET_RSP     0x0002
#define PERDITION_PACKET_STR_REQ 0x0003

#define PERDITION_PACKET_CS_SHA1 0x00000004
#define PERDITION_PACKET_CS_MD5  0x00000002
#define PERDITION_PACKET_CS_ROLL 0x00000001
#define PERDITION_PACKET_CS_NONE 0x00000000

typedef struct {
	uint32_t magic;
	uint16_t version;
	uint16_t flags;
	uint16_t length;
	uint16_t cs_type;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
} perdition_packet_head_t;

typedef struct {
	uint32_t time;
	char   cs[20]; /* 192 bit checksum */
} perdition_packet_tail_sha1_t;

typedef struct {
	uint32_t time;
	char   cs[16]; /* 128 bit checksum */
} perdition_packet_tail_md5_t;

typedef struct {
	uint32_t cs; /* 32 bit checksum */
} perdition_packet_tail_roll_t;

typedef void perdition_packet_tail_none_t;

typedef union {
	perdition_packet_tail_sha1_t sha1;
	perdition_packet_tail_md5_t md5;
	perdition_packet_tail_roll_t roll;
} perdition_packet_tail_t;

#define PERDITION_PACKET_MAX_PACKET_LEN 65000 /* 64kbyes, less a bit 
						 * for overhead */
#define PERDITION_PACKET_MAX_BODY_LEN \
	( PERDITION_PACKET_MAX_PACKET_LEN - sizeof(perdition_packet_tail_t) )

typedef struct {
	perdition_packet_head_t head;
	char body[PERDITION_PACKET_MAX_BODY_LEN];
	perdition_packet_tail_t tail;
} perdition_packet_t;

typedef struct {
	uint16_t length;
	const unsigned char *data;
} perdition_packet_str_t;

static inline void perdition_packet_str_pack(perdition_packet_str_t *p_str,
					     char *buf)
{
	p_str->data = (unsigned char *) buf;
	p_str->length = buf ? strlen(buf) : 0;
}

#define PERDITION_PACKET_STR_PACK(p_str, str) \
	perdition_packet_str_pack(&p_str, str);

perdition_packet_t *
perdition_packet_create(void);

void
perdition_packet_destroy(perdition_packet_t *packet);

int
perdition_packet_init_v1_req(perdition_packet_t **packet,
		uint16_t cs_type,
		uint32_t saddr, uint16_t sport,
		uint32_t daddr, uint16_t dport, 
		perdition_packet_str_t *key,
		perdition_packet_str_t *domain_delimiter);

int
perdition_packet_init_v1_str_req(perdition_packet_t **packet,
				 uint16_t cs_type,
				 perdition_packet_str_t *saddr,
				 perdition_packet_str_t *sport,
				 perdition_packet_str_t *daddr,
				 perdition_packet_str_t *dport,
				 perdition_packet_str_t *key,
				 perdition_packet_str_t *domain_delimiter);

int
perdition_packet_init_v1_rsp(perdition_packet_t **packet,
		uint16_t cs_type,
		perdition_packet_str_t *user,
		perdition_packet_str_t *server,
		perdition_packet_str_t *port);

int
perdition_packet_verify_v1_req(perdition_packet_t *packet,
		size_t len, perdition_packet_str_t *key,
		perdition_packet_str_t *domain_delimiter);

int
perdition_packet_verify_v1_str_req(perdition_packet_t *packet, size_t len,
				   perdition_packet_str_t *saddr,
				   perdition_packet_str_t *sport,
				   perdition_packet_str_t *daddr,
				   perdition_packet_str_t *dport,
				   perdition_packet_str_t *key,
				   perdition_packet_str_t *domain_delimiter);

int
perdition_packet_verify_v1_rsp(perdition_packet_t *packet,
		size_t len, perdition_packet_str_t *user,
		perdition_packet_str_t *server,
		perdition_packet_str_t *port);

#endif /* PERDITION_PACKET_H */
