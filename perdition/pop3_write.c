/**********************************************************************
 * pop3_write.c                                          September 1999
 * Horms                                             horms@verge.net.au
 *
 * Write POP3 protocol commands and responses
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

#include "pop3_write.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * pop3_write
 * Display an message of the form
 *       <command>[ <string>]
 * or
 *       <string>
 * Pre: io: io_t to write to
 *      flag: flag to pass to str_write as per str.h
 *      command: command in message sent
 *           if NULL then only string is written
 *      nargs: number of arguments after fmt
 *      fmt: format passed used to form string
 *      ...: arguments for fmt
 * Return 0 on success
 *        -1 otherwise
 **********************************************************************/

static char __pop3_write_fmt_str[MAX_LINE_LENGTH];

static const char *__pop3_write_fmt(io_t *UNUSED(io), flag_t *flag,
		const char *command, const char *fmt)
{
	char *new_fmt_end = NULL;
	size_t command_len;

	/* Fast Path */
	if(!command) {
		return(fmt);
	}

	/* Slow Path */

	memset(__pop3_write_fmt_str, 0, MAX_LINE_LENGTH);

	command_len = strlen(command);

	memcpy(__pop3_write_fmt_str, command, command_len);
	new_fmt_end = __pop3_write_fmt_str + command_len;

	if (fmt && *fmt) {
		size_t fmt_len = strlen(fmt);
		*(new_fmt_end) = ' ';
		memcpy(new_fmt_end + 1, fmt, fmt_len);
	        new_fmt_end += fmt_len + 1;
	}

	if (!(*flag & WRITE_STR_NO_CLLF)) {
		memcpy(new_fmt_end, "\r\n", 2);
		*flag |= WRITE_STR_NO_CLLF;
	}

	return(__pop3_write_fmt_str);
}

int pop3_vwrite(io_t *io, flag_t flag, const char *command,
		size_t nargs, const char *fmt, va_list ap)
{
	const char *new_fmt = NULL;

	new_fmt = __pop3_write_fmt(io, &flag, command, fmt);

	if (str_vwrite(io, flag, nargs, new_fmt, ap) < 0) {
		VANESSA_LOGGER_DEBUG("str_vwrite");
		return -1;
	}

	return 0;
}

int pop3_write(io_t *io, flag_t flag, const char *command,
	       size_t nargs, const char *fmt, ...)
{
	va_list ap;
	int status = -1;

	va_start(ap, fmt);
	if (pop3_vwrite(io, flag, command, nargs, fmt, ap) < 0) {
		VANESSA_LOGGER_DEBUG("str_vwrite");
		goto err;
	}

	status = 0;
err:
	va_end(ap);
	return status;
}

