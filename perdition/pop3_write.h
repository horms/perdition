/**********************************************************************
 * pop3_write.h                                          September 1999
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

#ifndef POP3_WRITE_FLIM
#define POP3_WRITE_FLIM

#include <stdarg.h>

#include "log.h"
#include "str.h"
#include "token.h"
#include "unused.h"

#define POP3_GREETING "POP3 perditon ready on"
#define POP3_QUIT "QUIT"
#define POP3_OK "+OK"
#define POP3_ERR "-ERR"
#define POP3_CAPA_END "."
#define POP3_CAPA_CONT "S:"
#define POP3_CAPABILITY_DELIMITER "."
#define POP3_OLD_CAPABILITY_DELIMITER "  "
#define POP3_DEFAULT_PORT_NAME "pop3"
#define POP3_DEFAULT_PORT_NUMBER "110"
#define POP3S_DEFAULT_PORT_NAME "pop3s"
#define POP3S_DEFAULT_PORT_NUMBER "995"

#define POP3_CMD_LEN  4
#define POP3_CMD_AUTH "AUTH"
#define POP3_CMD_CAPA "CAPA"
#define POP3_CMD_STLS "STLS"
#define POP3_CMD_USER "USER"
#define POP3_CMD_PASS "PASS"
#define POP3_CMD_QUIT "QUIT"


/**********************************************************************
 * pop3_write
 * Display an message of the form <command> [<string>]
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

int pop3_vwrite(io_t *io, const flag_t flag, const char *command,
		const size_t nargs, const char *fmt, va_list ap);

int pop3_write(io_t *io, const flag_t flag, const char *command,
	       const size_t nargs, const char *fmt, ...);

/**********************************************************************
 * pop3_write_str
 * Display an message of the form <command> [<string>]
 * Pre: io: io_t to write to
 *      flag: flag to pass to str_write as per str.h
 *      tag: ignored
 *      command: command in message sent
 *           if NULL then only string is written
 *      string: string, omitted if NULL
 *           At least one of command and string must be non-NULL
 * Return 0 on success
 *        -1 otherwise
 **********************************************************************/

static inline int
pop3_write_str(io_t *io, const flag_t flag, const token_t *UNUSED(tag),
	       const char *command, const char *str) {
	if (str)
		return pop3_write(io, flag, command, 1, "%s", str);
	return pop3_write(io, flag, command, 0, NULL);
}

#endif

