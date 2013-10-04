#include "auth.h"
#include "base64.h"
#include "buf.h"
#include "str.h"
#include "unused.h"

#include <vanessa_logger.h>

#if WITH_LIBIDN
#include <stringprep.h>

static char *saslprep(const char *in)
{
	int status;
	char *out;

	status = stringprep_profile(in, &out, "SASLprep", 0);
	if (status != STRINGPREP_OK) {
		VANESSA_LOGGER_DEBUG_UNSAFE("stringprep_profile: \"%s\"",
					    stringprep_strerror(status));
		return NULL;
	}

	return out;
}

static void saslprep_str_free(char *out)
{
	free(out);
}

#else
static char *saslprep(char *in)
{
	return in;
}

static void saslprep_str_free(char *UNUSED(out))
{
	;
}
#endif

/**********************************************************************
 * sasl_plain_challenge_decode
 * Decode a SASL PLAIN challenge
 * pre: challenge: the challenge
 * return: .auth: seeded auth structure
 *         .status: auth_status_ok on success
 *                  auth_status_invalid if the challenge is invalid
 *                  auth_status_error on internal error
 **********************************************************************/

struct auth_status sasl_plain_challenge_decode(char *challenge)
{
	STRUCT_CONST_BUF(in);
	STRUCT_BUF(out);
	STRUCT_AUTH_STATUS(as);
	char *authorisation_id = NULL, *authentication_id = NULL;
	char *passwd = NULL, *base64_data = NULL, *tmp = NULL;

	in.data = challenge;
	in.len = strlen(challenge);
	out = base64_decode(&in);
	if (buf_is_err(&out)) {
		if (out.len) {
			VANESSA_LOGGER_DEBUG("base64_decode");
			goto err;
		}
		as.reason = "Invalid base64 encoded challenge, mate";
		as.status = auth_status_invalid;
		goto err;
	}
	base64_data = out.data;

	/* Note about the use of strn_to_str() below.
	 *
	 * This may over-allocate and result in a string with
	 * more than one '\0', but it won't over-run and anything
	 * after the first '\0' will subsequently be ignored */

	if (out.len == 0) {
		as.reason = "Empty challenge, mate";
		as.status = auth_status_invalid;
		goto err;
	}

	if (*out.data) {
		char *saslprep_str;

		authorisation_id = strn_to_str(out.data, out.len);
		if (!authorisation_id) {
			VANESSA_LOGGER_DEBUG("strdup authorisation_id");
			goto err;
		}

		saslprep_str = authorisation_id;
		authorisation_id = saslprep(authorisation_id);
		saslprep_str_free(saslprep_str);
		if (!authorisation_id) {
			VANESSA_LOGGER_DEBUG("saslprep "
					     "authorisation_id");
			goto err;
		}

		out.data += strlen(authorisation_id);
		out.len -= strlen(authorisation_id);
	}

	if (out.len < 1) {
		as.reason = "Challenge has no authentication id, mate";
		as.status = -1;
		goto err;
	}

	out.data++;
	out.len--;

	authentication_id = strn_to_str(out.data, out.len);
	if (!authentication_id) {
		VANESSA_LOGGER_DEBUG("strdup authentication_id");
		goto err;
	}
	out.data += strlen(authentication_id);
	out.len -= strlen(authentication_id);

	tmp = saslprep(authentication_id);
	if (!tmp) {
		VANESSA_LOGGER_DEBUG("saslprep: authentication_id");
		goto err;
	}
	if (tmp != authentication_id) {
		free(authentication_id);
		authentication_id = tmp;
	}

	if (!*authentication_id) {
		as.reason = "Empty authentication id, mate";
		as.status = auth_status_invalid;
		goto err;
	}

	if (out.len < 1) {
		as.reason = "Challenge has no password, mate";
		as.status = auth_status_invalid;
		goto err;
	}

	out.data++;
	out.len--;

	passwd = strn_to_str(out.data, out.len);
	if (!passwd) {
		VANESSA_LOGGER_DEBUG("strdup passwd");
		goto err;
	}
	out.len -= strlen(passwd);

	if (out.len) {
		as.reason = "Trailing garbage in challenge, mate";
		as.status = -1;
		goto err;
	}

	as.auth = auth_set_sasl_plain(authorisation_id,
				      authentication_id, passwd);
	authorisation_id = authentication_id = passwd = NULL;
	as.status = auth_status_ok;

err:
	free(authorisation_id);
	free(authentication_id);
	free(passwd);
	free(base64_data);
	return as;
}

/**********************************************************************
 * sasl_plain_challenge_encode
 * Encode a SASL PLAIN challenge
 * pre: auth: seeded auth structure
 * return: encoded challenge
 *         NULL on error
 **********************************************************************/

char * sasl_plain_challenge_encode(const struct auth *auth)
{
	STRUCT_BUF(in);
	STRUCT_BUF(out);
	char *p, *out_str = NULL;

	if (auth->authorisation_id)
		in.len += strlen(auth->authorisation_id);
	in.len += 1 + strlen(auth->authentication_id) + 1;
	in.len += strlen(auth->passwd);

	in.data = malloc(in.len);
	if (!in.len) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		goto err;
	}

	p = in.data;
	if (auth->authorisation_id) {
		strcpy(in.data, auth->authorisation_id);
		p += strlen(auth->authorisation_id) + 1;
	} else {
		in.data[0] = '\0';
		p++;
	}
	strcpy(p, auth->authentication_id);
	p += strlen(auth->authentication_id) + 1;
	memcpy(p, auth->passwd, strlen(auth->passwd));

	out = base64_encode(&in);
	if (buf_is_err(&out)) {
		VANESSA_LOGGER_DEBUG("base64_encode");
		goto err;
	}

	out_str = strn_to_str(out.data, out.len);
	if (!out_str) {
		VANESSA_LOGGER_DEBUG("strn_to_str");
		goto err;
	}

err:
	free(out.data);
	free(in.data);
	return out_str;
}
