#ifndef PERDIITON_MANAGESIEVE_WRITE_H
#define PERDIITON_MANAGESIEVE_WRITE_H

#include "io.h"
#include "token.h"
#include "unused.h"

#define MANAGESIEVE_GREETING	"predition ready on"
#define MANAGESIEVE_QUIT	"LOGOUT"
#define MANAGESIEVE_OK	"OK"
#define MANAGESIEVE_NO	"NO"
#define MANAGESIEVE_BYE	"BYE"

#define MANAGESIEVE_DEFAULT_PORT "2000"

/**********************************************************************
 * managesieve_write
 * Display an message of the form
 *	 <command>[ <string>]
 * or
 *	 <string>
 * Pre: io: io_t to write to
 *	flag: flag to pass to str_write as per str.h
 *	tag: ignored
 *	command: command in message sent
 *		 if NULL then only string is written
 *	nargs: number of arguments after fmt
 *	fmt: format passed used to form string
 *	...: arguments for fmt
 * Return 0 on success
 *	  -1 otherwise
 **********************************************************************/

int managesieve_write(io_t *io, flag_t flag, const token_t *tag,
		      const char *command, size_t nargs, const char *fmt, ...);

static inline int
managesieve_write_str(io_t *io, const flag_t flag, const token_t *UNUSED(tag),
	       const char *command, const char *str) {
	if (str)
		return managesieve_write(io, flag, NULL, command, 1, "%s", str);
	return managesieve_write(io, flag, NULL, command, 0, NULL);
}

#endif /* PERDIITON_MANAGESIEVE_WRITE_H */
