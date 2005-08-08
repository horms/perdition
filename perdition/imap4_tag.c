/**********************************************************************
 * imap4_tag.c                                            December 2002
 * Horms                                             horms@verge.net.au
 *
 * IMAP4 tag handler
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

#include "imap4_tag.h"
#include "token.h"
#include "log.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define IMAP_TAG_START "flim07"


/**********************************************************************
 * imap4_tag_create
 * Create a token suitable for use as an imap tag
 * pre: none
 * post: token is created and initialised
 * return: token
 *         NULL on error
 **********************************************************************/

token_t *imap4_tag_create(void)
{
	char *buf;
	token_t *tag;

	tag = token_create();
	if(!tag) {
		VANESSA_LOGGER_DEBUG("create_token");
		return(NULL);
	}

	buf = strdup(IMAP_TAG_START);
	if(!buf) {
		VANESSA_LOGGER_DEBUG("strdup");
		token_destroy(&tag);
		return(NULL);
	}

	token_assign(tag, (unsigned char *)buf, strlen(buf), TOKEN_NONE);

	return(tag);
}


/**********************************************************************
 * imap4_tag_inc
 * Increment a token being used as an imap token
 * pre: token to increment
 * post: token is incremented such that it may be used as the next
 *       imap tag
 * return: none
 **********************************************************************/

void imap4_tag_inc(token_t *tag) 
{
	unsigned char *buf;
	size_t len;
	int c;
	int last;

	if(!tag) {
		return;
	}

	buf = token_buf(tag);
	len = token_len(tag);

	/* Order is 0-9,a-z,A-Z */
	while(len-- > 0) {
		last = 1;
		c = (int)*(buf+len);
		if(isdigit(c)) {
			if(c == '9') {
				c = 'a';
			}
			else {
				c++;
			}
		}
		else if(islower(c)) {
			if(c == 'z') {
				c = 'A';
			}
			else {
				c++;
			}
		}
		else if(isupper(c) && c != 'Z') {
				c++;
		}
		else {
			c = '0';
			last = 0;
		}

		*(buf+len) = (char)c;

		if(last) {
			break;
		}
	}
}

