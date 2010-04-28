#ifndef PERDIITON_MANAGESIEVE_WRITE_H
#define PERDIITON_MANAGESIEVE_WRITE_H

#include "io.h"
#include "managesieve_response_code.h"
#include "perdition_types.h"
#include "token.h"
#include "unused.h"

#define MANAGESIEVE_GREETING	"predition ready on"
#define MANAGESIEVE_QUIT	"LOGOUT"
#define MANAGESIEVE_OK	"OK"
#define MANAGESIEVE_NO	"NO"
#define MANAGESIEVE_BYE	"BYE"

#define MANAGESIEVE_DEFAULT_PORT "2000"

/**********************************************************************
  * managesieve_write_raw
  *       message: must not be NULL
  *       message: must not be NULL
  * Display an message without any alteration
  **********************************************************************/

int managesieve_write_raw(io_t *io, const char *message);

/**********************************************************************
  * managesieve_write
  * pre: io: io_t to write to
  *       flag: PERDITION_CLIENT or PERDITION_SERVER
  *       command: must not be NULL
  *       rc: response code
  *       message: must not be NULL
  * Display an message of the form <command> [<rc>] <message>
  **********************************************************************/

int managesieve_write(io_t *io, flag_t flag, const char *command,
		      const struct managesieve_response_code *rc,
		      const char *message);

/**********************************************************************
 * managesieve_write_str
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
managesieve_write_str(io_t *io, const flag_t flag, const token_t *UNUSED(tag),
		      const char *command, const char *str)
{
	if (!command && !str)
		return -1;
	if (!command)
		/* This is a special case used to handle opt.server_resp_line,
		 * and jsut requires str to be written verbatim. */
		 return str_write(io, WRITE_STR_NO_CLLF, 1, "%s", str);
	return managesieve_write(io, flag, command, NULL, str);
}

#endif /* PERDIITON_MANAGESIEVE_WRITE_H */
