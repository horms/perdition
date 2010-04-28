#include "acap.h"
#include "managesieve_response_code.h"
#include "managesieve_write.h"
#include "str.h"
#include "io.h"
#include "perdition_types.h"

#include <stdarg.h>
#include <vanessa_logger.h>

/**********************************************************************
  * managesieve_write_raw
  *       message: must not be NULL
  *       message: must not be NULL
  * Display an message without any alteration
  **********************************************************************/

int managesieve_write_raw(io_t *io, const char *message)
{
	if (str_write(io, 0, 1, "%s", message) < 0) {
		VANESSA_LOGGER_DEBUG("str_write");
		return -1;
	}
	return 0;
}

static int managesieve_write_list(io_t *io, size_t n, ...)
{
	char *out = NULL;
	const char *str;
	size_t i, x, len = 0;
	int status = -1;
	va_list ap, aq;

	if (!n) {
		VANESSA_LOGGER_DEBUG("No strings");
		goto err;
	}

	va_start(ap, n);
	va_copy(aq, ap);
	for (i = 0; i < n; i++) {
		str = va_arg(ap, const char *);
		if (!str)
			continue;
		len += strlen(str) + 1;
	}
	va_end(ap);

	if (!len) {
		VANESSA_LOGGER_DEBUG("No non-NULL strings");
		goto err;
	}

	out = malloc(len);
	if (!out) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		goto err;
	}

	*out = '\0';

	x = 0;
	va_start(aq, n);
	for (i = 0; i < n; i++) {
		str = va_arg(aq, const char *);
		if (!str)
			continue;
		if (x)
			strcat(out, " ");
		strcat(out, str);
		x++;
	}
	va_end(aq);

	if (managesieve_write_raw(io, out) < 0) {
		VANESSA_LOGGER_DEBUG("managesieve_write_raw");
		goto err;
	}

	status = 0;
err:
	free(out);
	return status;
}

int managesieve_write(io_t *io, flag_t flag, const char *command,
		      const struct managesieve_response_code *rc,
		      const char *message)
{
	char **rc_str = NULL, **rc_str_p, *tail;
	const char *cmd;
	STRUCT_ACAP(msg_acap);
	int status = -1;

	if (message) {
		msg_acap = acap_from_str(message, flag);
		if (acap_is_zero(&msg_acap)) {
			VANESSA_LOGGER_DEBUG("acap_from_str");
			return -1;
		}
	}

	if (!rc) {
		if (managesieve_write_list(io, 2, command, msg_acap.a) < 0) {
			VANESSA_LOGGER_DEBUG("managesieve_write_list no rc");
			goto err;
		}
	} else {
		rc_str = managesieve_response_str(rc, flag);
		if (!rc_str) {
			VANESSA_LOGGER_DEBUG("managesieve_response_str");
			goto err;
		}

		cmd = command;
		tail = NULL;
		for (rc_str_p = rc_str + 1; *rc_str_p; rc_str_p++) {
			if (!*(rc_str_p + 1))
				tail = msg_acap.a;
			if (managesieve_write_list(io, 3, cmd,
						  *rc_str_p, tail) < 0) {
				VANESSA_LOGGER_DEBUG("managesieve_write_list "
						    "rc");
				goto err;
			}
			cmd = NULL;
		}
	}

	if (msg_acap.b) {
		if (managesieve_write_raw(io, msg_acap.b) < 0) {
			VANESSA_LOGGER_DEBUG("str_vwrite no rc b");
			goto err;
		}
	}

	status = 0;
err:
	acap_free(&msg_acap);
	managesieve_response_str_free(rc_str);
	return status;
}
