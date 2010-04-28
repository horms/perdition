#include "acap.h"
#include "perdition_types.h"

#include <stdlib.h>
#include <stdio.h>
#include <vanessa_logger.h>

static void acap_zero(struct acap *acap)
{
	acap->a = NULL;
	acap->b = NULL;
}

void acap_free(struct acap *acap)
{
	if (!acap)
		return;
	free(acap->a);
	acap_zero(acap);
}

static size_t log_10(size_t n)
{
	size_t log = 0;

	while (1) {
		n = n/10;
		if (!n)
			break;
		log++;
	}

	return log;
}

static size_t n_len(size_t n)
{
	return log_10(n) + 1;
}

static struct acap acap_quoted_from_str(const char *str)
{
	/* a: "\"str\""
	 * b: NULL
	 */

	STRUCT_ACAP(out);

	out.a = malloc(1 + strlen(str) + 2);
	if (!out.a) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		return out;
	}

	strcpy(out.a, "\"");
	strcat(out.a, str);
	strcat(out.a, "\"");

	return out;
}

static struct acap acap_any_literal_from_str(const char *str,
					     const char *extra)
{
	/* a: "{n+}" or "{n}"
	 * b: "str"
	 */

	size_t n;
	STRUCT_ACAP(out);

	n = strlen(str);

	out.a = malloc(1 + n_len(n) + strlen(extra) + 2);
	if (!out.a) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		return out;
	}

	sprintf(out.a, "{%d%s}", n, extra);

	out.b = str;

	return out;
}

static struct acap acap_literal_from_str(const char *str)
{
	return acap_any_literal_from_str(str, "");
}

static struct acap acap_non_sync_literal_from_str(const char *str)
{
	return acap_any_literal_from_str(str, "+");
}

struct acap acap_from_str(const char *str, flag_t flag)
{
	if (!strchr(str, '\r') && !strchr(str, '\n'))
		return acap_quoted_from_str(str);
	if (flag & PERDITION_CLIENT)
		return acap_non_sync_literal_from_str(str);

	return acap_literal_from_str(str);
}
