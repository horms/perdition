/**********************************************************************
 * imap4_tag.h                                            December 2002
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/


#ifndef _IMAP4_TAG_H
#define _IMAP4_TAG_H

#include "token.h"

/**********************************************************************
 * imap4_tag_create
 * Create a token suitable for use as an imap tag
 * pre: none
 * post: token is created and initialised
 * return: token
 *         NULL on error
 **********************************************************************/

token_t *imap4_tag_create(void);


/**********************************************************************
 * imap4_tag_destroy
 * Destroy a token used as an imap tag
 * pre: token to destroy
 * post: token is destroyed
 * return: none
 **********************************************************************/

#define imap4_tag_destroy(_t) token_destroy(_t)


/**********************************************************************
 * imap4_tag_inc
 * Increment a token being used as an imap token
 * pre: token to increment
 * post: token is incremented such that it may be used as the next
 *       imap tag
 * return: none
 **********************************************************************/

void imap4_tag_inc(token_t *tag);

#endif /* _IMAP4_TAG_H */
