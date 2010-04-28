#include "io.h"
#include "token.h"
#include "managesieve_write.h"
#include "unused.h"

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

int managesieve_write(io_t *UNUSED(io), flag_t UNUSED(flag),
		      const token_t *UNUSED(tag), const char *UNUSED(command),
		      size_t UNUSED(nargs), const char *UNUSED(fmt), ...)
{
	return -1;
}
