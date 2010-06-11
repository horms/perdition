#include "acap_token.h"
#include "token.h"
#include "queue_func.h"

#include <vanessa_adt.h>
#include <ctype.h>
#include <limits.h>

struct acap_token_status {
	enum acap_type type;
	size_t len;
};

#define STRUCT_ACAP_TOKEN_STATUS(name) \
	struct acap_token_status (name) = { .type = acap_err }

/* cheat and trim this value down a bit */
#define REAL_ACAP_LITERAL_MAX 4294967296
#if REAL_ACAP_LITERAL_MAX > SIZE_MAX
#define ACAP_LITERAL_MAX SIZE_MAX
#else
#define ACAP_LITERAL_MAX REAL_ACAP_LITERAL_MAX
#endif

#define ACAP_QUOTED_MAX 1024
#define ACAP_ATOM_MAX 1024

static int atom_char(int c)
{
	return c == '!' ||
	       (c >= 0x23 && c <= 0x27) ||
	       (c >= 0x2A && c <= 0x5B) ||
	       (c >= 0x5D && c <= 0x7A) ||
	       (c >= 0x7C && c <= 0x7E);
}

static int quoted_special(int c)
{
	return c == '\"' || c == '\\';
}

static int utf8_1(int c)
{
	return c >= 0x80 && c <= 0xBF;
}

static int utf8_2(int c0, int c1)
{
	return c0 >= 0xC0 && c0 <= 0xDF && utf8_1(c1);
}

static int utf8_3(int c0, int c1, int c2)
{
	return c0 >= 0xE0 && c1 <= 0xEF && utf8_1(c1) && utf8_1(c2);
}

static int utf8_4(int c0, int c1, int c2, int c3)
{
	return c0 >= 0xF0 && c1 <= 0xF7 &&
		utf8_1(c1) && utf8_1(c2) && utf8_1(c3);
}

static int safe_char(int c)
{
	return c && c <= 0x7f && !quoted_special(c);
}

/* The ACAP RFC, 2422, allows for up to URF8-6. The managesievemanage draft,
 * which is consistent with the UTF-8 RFC 3629, only allows up to UTF8-4.
 * The reason being that Unicode code-points are up to 24bits long, so UTF8-5
 * and UTF8-6 are not possible.
 * http://www.ietf.org/mail-archive/web/sieve/current/msg04696.html */

static int safe_utf8_char(const char *buf, size_t n)
{
	if (n > 0 && safe_char(buf[0]))
		return 1;
	if (n > 1 && utf8_2(buf[0], buf[1]))
		return 2;
	if (n > 2 && utf8_3(buf[0], buf[1], buf[2]))
		return 3;
	if (n > 3 && utf8_4(buf[0], buf[1], buf[2], buf[3]))
		return 4;
	return 0;
}

static int quoted_char(const char *buf, size_t n) {
	int j;

	j = safe_utf8_char(buf, n);
	if (j)
		return j;

	/* ACAP RFC 2244 specifies '\\' as the escape character,
	 * however draft-ietf-sieve-managesieve-09.txt: uses '"'.
	 * The latter is a specification bug.
	 * http://www.ietf.org/mail-archive/web/sieve/current/msg04696.html */
	 if (n > 1 && buf[0] == '\\' && quoted_special(buf[1]))
		return 2;

	return 0;
}

static int acap_strn_is_atom(const char *buf, size_t n)
{
	size_t i;

	if (n > ACAP_ATOM_MAX)
		return 0;

	for (i = 0; i < n; i++)
		if (!atom_char(buf[i]))
			return 0;

	return 1;
}

static int acap_strn_is_quoted(const char *buf, size_t n)
{
	size_t i, j;

	if (n < 2 || n > ACAP_QUOTED_MAX || buf[0] != '"' || buf[n - 1] != '"')
		return 0;

	for (i = 1; i < n - 1;) {
		j = quoted_char(buf + i, n - 1 - i);
		if (!j)
			return 0;
		i += j;
	}

	return 1;
}

static struct acap_token_status acap_token_status(const token_t *token)
{
	char *t_buf, *end, *p;
	unsigned long len;
	size_t t_len;
	STRUCT_ACAP_TOKEN_STATUS(status);

	t_buf = (char *)token_buf(token);
	if (!t_buf)
		goto err;

	t_len = token_len(token);
	end = t_buf + t_len;

	/* Check for surrounding {} */
	if (*t_buf != '{' || *(end - 1) != '}') {
		if (acap_strn_is_atom(t_buf, t_len)) {
			status.type = acap_atom;
			status.len = t_len;
		} else if (acap_strn_is_quoted(t_buf, t_len)) {
			status.type = acap_quoted;
			status.len = t_len - 2;
		} else
			goto err;
		return status;
	}

	/* Must be at the end of a line */
	if (!token_is_eol(token))
		goto err;

	/* There must be something inside the '{' and '}' */
	if (t_len < 3)
		goto err;

	/* If the trailing character is a + then it is a
	 * non_synchronising literal */
	if (*(end - 2) == '+') {
		status.type = acap_non_sychronising_literal;
		if (t_len < 4)
			goto err;
		end--;
		t_len--;
	} else
		status.type = acap_sychronising_literal;

	/* Convert it into binary */
	len = strtoul(t_buf+1, &p, 10);
	if (len == ULONG_MAX)
		goto err;
	/* Rather large litereals are legal */
	if (len > SIZE_MAX || len > ACAP_LITERAL_MAX)
		goto err;
	if (p != end - 1)
		goto err;

	status.len = len;
	return status;

err:
	status.type = acap_err;
	return status;
}

static struct acap_token_wrapper_status
acap_token_wrapper_strn(vanessa_queue_t *q, token_t *t,
			size_t offset, size_t len, enum acap_type type)
{
	STRUCT_ACAP_TOKEN_WRAPPER_STATUS(status);

	status.type = type;

	status.str = strn_to_str((char *)token_buf(t) + offset, len);
	if (!status.str) {
		VANESSA_LOGGER_DEBUG_ERRNO("token_to_str");
		vanessa_queue_destroy(q);
		goto err;
	}

	if (vanessa_queue_length(q))
		status.q = q;

	status.status = 0;
err:
	if (status.q != q)
		vanessa_queue_destroy(q);
	token_destroy(&t);
	return status;
}

static struct acap_token_wrapper_status
acap_token_wrapper_atom(vanessa_queue_t *q, token_t *t)
{
	return acap_token_wrapper_strn(q, t, 0, token_len(t), acap_atom);
}

static struct acap_token_wrapper_status
acap_token_wrapper_quoted(vanessa_queue_t *q, token_t *t)
{
	return acap_token_wrapper_strn(q, t, 1, token_len(t) - 2,
				       acap_quoted);
}

static struct acap_token_wrapper_status
acap_token_wrapper_literal(io_t *io, flag_t flag, vanessa_queue_t *q,
			  token_t *t, size_t len, enum acap_type type)
{
	char *str = NULL;
	const char *log_str;
	STRUCT_ACAP_TOKEN_WRAPPER_STATUS(status);

	status.type = type;

	if (!token_is_eol(t)) {
		status.status = -1;
		goto err;
	}

	vanessa_queue_destroy(q);
	q = NULL;
	token_destroy(&t);

	if (len == 0) {
		status.str = strdup("");
		if (!status.str) {
			VANESSA_LOGGER_DEBUG_ERRNO("strdup");
			goto err;
		}
		goto out;
	}

	if (flag & PERDITION_CLIENT)
		log_str = PERDITION_LOG_STR_CLIENT;
	else
		log_str = PERDITION_LOG_STR_REAL;

	t = token_read(io, NULL, NULL, TOKEN_ACAP_LITERAL, len, log_str);
	if (!t) {
		VANESSA_LOGGER_DEBUG("token_read");
		goto err;
	}

	str = token_to_string(t, TOKEN_NO_STRIP);
	if (!str) {
		VANESSA_LOGGER_DEBUG("token_to_string");
		goto err;
	}

	token_destroy(&t);

	q = read_line(io, NULL, NULL, TOKEN_ACAP_ATOM, 0, log_str);
	if (!q) {
		VANESSA_LOGGER_DEBUG("read_line");
		goto err;
	}

	q = vanessa_queue_pop(q, (void **)&t);
	if (!q) {
		VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
		goto err;
	}

	if (token_len(t)) {
		/* Trailing garbage */
		status.status = -1;
		goto err;
	}

	status.str = str;

	if (vanessa_queue_length(q))
		status.q = q;

out:
	status.status = 0;
err:
	token_destroy(&t);
	if (status.q != q)
		vanessa_queue_destroy(q);
	if (!status.str)
		free(str);
	return status;
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
acap_token_wrapper(io_t *io, flag_t flag, vanessa_queue_t *q)
{
	token_t *t = NULL;
	STRUCT_ACAP_TOKEN_STATUS(token_status);
	STRUCT_ACAP_TOKEN_WRAPPER_STATUS(wrapper_status);

	q = vanessa_queue_pop(q, (void **)&t);
	if (!q) {
		VANESSA_LOGGER_DEBUG("vanessa_queue_pop");
		goto err;
	}

	token_status = acap_token_status(t);

	switch (token_status.type) {
	case acap_err:
		wrapper_status.status = -1;
		break;
	case acap_atom:
		return acap_token_wrapper_atom(q, t);
	case acap_quoted:
		return acap_token_wrapper_quoted(q, t);
	case acap_sychronising_literal:
	case acap_non_sychronising_literal:
		return acap_token_wrapper_literal(io, flag, q, t,
						  token_status.len,
						  token_status.type);
	}

err:
	token_destroy(&t);
	vanessa_queue_destroy(q);
	return wrapper_status;
}
