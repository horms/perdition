#include "managesieve_response_code.h"
#include "acap.h"
#include "perdition_types.h"

#include <vanessa_logger.h>

void managesieve_response_str_free(char **str)
{
	char **p;

	if (!str)
		return;

	for (p = str; *p; p++)
		free(*p);

	free(str);
}

char **managesieve_response_str(const struct managesieve_response_code *rc,
				flag_t flag)
{
	size_t len;
	char **arg_p, **out = NULL, **out_p;
	STRUCT_ACAP(acap);

	if (!rc->atom) {
		VANESSA_LOGGER_DEBUG("no atom");
		return NULL;
	}

	len = 0;
	for (arg_p = rc->arg; arg_p && *arg_p; arg_p++)
		len++;

	out = calloc(sizeof(*out), len + 2);
	if (!out) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc");
		goto err;
	}

	out_p = out;

	*out_p = malloc(1 + strlen(rc->atom) + 1);
	if (!*out_p) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		goto err;
	}

	strcpy(*out_p, "(");
	strcat(*out_p, rc->atom);

	for (arg_p = rc->arg; arg_p && *arg_p; arg_p++) {
		acap = acap_from_str(*arg_p, flag);
		if (acap_is_zero(&acap)) {
			VANESSA_LOGGER_DEBUG("acap_from_str");
			goto err;
		}

		*out_p = realloc(*out_p, strlen(*out_p) + 1 +
					 strlen(acap.a) + 1);
		if (!*out_p) {
			VANESSA_LOGGER_DEBUG_ERRNO("realloc body");
			goto err;
		}
		strcat(*out_p, " ");
		strcat(*out_p, acap.a);

		if (acap.b) {
			*++out_p = strdup(acap.b);
			if (!*out_p) {
				VANESSA_LOGGER_DEBUG_ERRNO("strdup b");
				goto err;
			}
		}

		acap_free(&acap);
	}

	*out_p = realloc(*out_p, strlen(*out_p) + 2);
	if (!*out_p) {
		VANESSA_LOGGER_DEBUG_ERRNO("realloc end");
		goto err;
	}
	strcat(*out_p, ")");

	return out;

err:
	acap_free(&acap);
	managesieve_response_str_free(out);
	return NULL;
}
