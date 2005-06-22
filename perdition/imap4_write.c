/**********************************************************************
 * imap4_write .c                                        September 1999
 * Horms                                             horms@verge.net.au
 *
 * Subroutines to write IMAP4 protocol output
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

#include "imap4_write.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * imap4_write
 * Display an message of the form 
 *       <tag> <command>[ <string>]
 * or
 *       <string>
 * Pre: io: io_t to write to
 *      flag: flag to pass to str_write as per str.h
 *      tag: tag to display
 *           if NULL, then IMAP4_UNTAGGED is used
 *      command: command in message sent
 *           if NULL then only string is written, no tag or command
 *      nargs: number of arguments after fmt
 *      fmt: format passed used to form string
 *      ...: arguments for fmt
 * Return 0 on success
 *        -1 otherwise
 **********************************************************************/

static char __imap4_write_fmt_str[MAX_LINE_LENGTH];

static const char *__imap4_write_fmt(io_t *io, flag_t *flag, 
		const token_t *tag, const char *command, const char *fmt)
{
	char *tag_str = NULL;
	char *new_fmt_end = NULL;
	size_t tag_str_len;
	size_t command_len;
	size_t fmt_len;

	/* Fast Path */
	if(!command && !tag) {
		return(fmt);
	}

	/* Slow Path */

	memset(__imap4_write_fmt_str, 0, MAX_LINE_LENGTH);

      	if(!tag) {
		tag_str = IMAP4_UNTAGGED;
		tag_str_len = strlen(IMAP4_UNTAGGED);
	}
	else {
		tag_str = token_buf(tag);
		tag_str_len = token_len(tag);
	}

	fmt_len = strlen(fmt);

	memcpy(__imap4_write_fmt_str, tag_str, tag_str_len);
	new_fmt_end = __imap4_write_fmt_str + tag_str_len;

	if(command){
		command_len = strlen(command);
		*(new_fmt_end) = ' ';
		memcpy(new_fmt_end + 1, command, command_len);
		new_fmt_end += command_len + 1;
	}

	if(*fmt){
		*(new_fmt_end) = ' ';
		memcpy(new_fmt_end + 1, fmt, fmt_len);
	        new_fmt_end += fmt_len + 1;
	}

	if (!(*flag & WRITE_STR_NO_CLLF)) {
		memcpy(new_fmt_end, "\r\n", 2);
		*flag |= WRITE_STR_NO_CLLF;
	}

	return(__imap4_write_fmt_str);
}

int imap4_write(io_t *io, flag_t flag, const token_t *tag, 
		const char *command, size_t nargs, const char *fmt, ...)
{
	const char *new_fmt = NULL;
	va_list ap;

	new_fmt = __imap4_write_fmt(io, &flag, tag, command, fmt);

	va_start(ap, fmt);
	if(str_vwrite(io, flag, nargs, new_fmt, ap)<0){
		VANESSA_LOGGER_DEBUG("str_vwrite");
		va_end(ap);
		return(-1);
	}
	va_end(ap);
  
  	return(0);
}
