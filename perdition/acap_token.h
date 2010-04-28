#ifndef PERDITON_ACAP_TOKEN_H
#define PERDITON_ACAP_TOKEN_H

#include "acap_token.h"
#include "token.h"

#include <vanessa_adt.h>

enum acap_type {
	acap_err = 0,
	acap_atom,
	acap_quoted,
	acap_sychronising_literal,
	acap_non_sychronising_literal
};

struct acap_token_wrapper_status {
	int status;
	enum acap_type type;
	vanessa_queue_t *q;
	char *str;
};

#define STRUCT_ACAP_TOKEN_WRAPPER_STATUS(name) \
	struct acap_token_wrapper_status (name) = \
		{ .status = -2, .type = acap_err, .q = NULL, .str = NULL }

static inline int
acap_token_wrapper_status_is_eol(struct acap_token_wrapper_status *status)
{
	return status->q == NULL;
}

/**********************************************************************
 * acap_token_wrapper
 * Interpret a token as a literal or quoted string.
 * pre: io: IO to read from if necessary
 *      flag: PERDITION_CLIENT or PERDITION_SERVER
 *      q: Queue of pending tokens, including input_token
 * return: seeded acap_token_wrapper_status
 *         .status
 *         0: success
 *            string of acap string is in .str
 *	      type of acap is in .type
 *            Use acap_token_wrapper_status_is_eol() to determine if the
 *	      eol followed the acap string. If not, residual data is in .q.
 *         -1: invalid acap token
 *         -2: other error
 *         NULL on error
 **********************************************************************/

struct acap_token_wrapper_status
acap_token_wrapper(io_t *io, flag_t flag, vanessa_queue_t *q);

#endif /* define PERDITON_ACAP_TOKEN_H */
