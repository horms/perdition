#ifndef MANAGESIEVE_RESPONSE_CORE_H
#define MANAGESIEVE_RESPONSE_CORE_H

#include "managesieve_response_code.h"
#include "perdition_types.h"

#include <vanessa_logger.h>
#include <vanessa_adt.h>

struct managesieve_response_code {
	const char *atom;
	char **arg;
};

#define STRUCT_MANAGESIEVE_RESPONSE_CODE(name) \
	struct managesieve_response_code (name) = { NULL, NULL }

/**********************************************************************
 * managesieve_response_str
 * Format a managesieve_response into strings suitable for sending on the wire
 * pre: rc: managesieve_response to format
 *      flag: PERDITION_CLIENT or PERDITION_SERVER
 * return: list of strings, on success.
 *         Should be freed using managesieve_response_str_free()
 *         NULL on error
 **********************************************************************/

char **managesieve_response_str(const struct managesieve_response_code *rc,
				flag_t flag);

/**********************************************************************
 * managesieve_response_str_free
 * Free the result of managesieve_response_str()
 * pre: str: list of strings, as returned by managesieve_response_str()
 * post: str and the strings it contains are freed
 * return: none
 **********************************************************************/

void managesieve_response_str_free(char **str);

#endif /* MANAGESIEVE_RESPONSE_CORE_H */
