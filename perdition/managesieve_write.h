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
#define MANAGESIEVE_CAPA_DELIMITER "  "

/* Reflect capabilities of
 * dovecot-1.2.10 +
 * dovecot-1.2-sieve-0.1.15 +
 * dovecot-1.2-managesieve-0.11.11 */
#define MANAGESIEVE_DEFAULT_CAPA \
	"\"IMPLEMENTATION\" \"perdition\""		\
	MANAGESIEVE_CAPA_DELIMITER			\
	"\"SIEVE\" \"comparator-i;octet "		\
		    "comparator-i;ascii-casemap "	\
		    "fileinto "				\
		    "reject "				\
		    "envelope "				\
		    "encoded-character "		\
		    "vacation "				\
		    "subaddress "			\
		    "comparator-i;ascii-numeric "	\
		    "relational "			\
		    "regex "				\
		    "imap4flags "			\
		    "copy "				\
		    "include "				\
		    "variables "			\
		    "body "				\
		    "enotify "				\
		    "environment "			\
		    "mailbox "				\
		    "date\""				\
	MANAGESIEVE_CAPA_DELIMITER			\
	"\"SASL\" \"PLAIN\""				\
	MANAGESIEVE_CAPA_DELIMITER			\
	"\"NOTIFY\" \"mailto\""				\
	MANAGESIEVE_CAPA_DELIMITER			\
	"\"VERSION\" \"" VERSION "\""

#define MANAGESIEVE_CAPA_STARTTLS "\"STARTTLS\""

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

static inline int
managesieve_ok(io_t *io, const struct managesieve_response_code *rc,
	       const char *message)
{
	return managesieve_write(io, PERDITION_SERVER,
				 MANAGESIEVE_OK, rc, message);
}
static inline int
managesieve_no(io_t *io, const struct managesieve_response_code *rc,
	       const char *message)
{
	sleep(PERDITION_AUTH_FAIL_SLEEP);
	return managesieve_write(io, PERDITION_SERVER,
				 MANAGESIEVE_NO, rc, message);
}

static inline int
managesieve_bye(io_t *io, const struct managesieve_response_code *rc,
		const char *message)
{
	sleep(PERDITION_AUTH_FAIL_SLEEP);
	return managesieve_write(io, PERDITION_SERVER,
				 MANAGESIEVE_BYE, rc, message);
}

#endif /* PERDIITON_MANAGESIEVE_WRITE_H */
