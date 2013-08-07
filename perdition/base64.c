#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

#include "log.h"
#include "buf.h"


/* Openssl's base64 encode places an '\n' after every 64 bytes of encoded
 * text and at the end of the encoded text */

static void base64_encode_clean(struct buf *buf)
{
	size_t i, o;

	for (i = 65, o = 64; i < buf->len; i += 65, o += 64)
		memmove(buf->data + o, buf->data + i, buf->len - i);

	buf->len -= (buf->len + 64) / 65;
	buf->data[buf->len] = '\0';
}

/**********************************************************************
 * base64_encode
 * pre: in: struct buf to decode
 * return: on success: { .buf = str, .len = len }
 *         on error: { .buf = NULL, .len = 0 }
 *         buf_is_err() can be used to test for { .buf == NULL }
 **********************************************************************/

struct buf base64_encode(const struct buf *in)
{
	char *b64_data;
	BIO *mem_bio, *b64_bio = NULL;
	long b64_len;
	int ilen;
	STRUCT_BUF(out);

	memset(&out, 0, sizeof(out));

	b64_bio = BIO_new(BIO_f_base64());
	if (!b64_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new b64_bio");
		goto err;
	}

	mem_bio = BIO_new(BIO_s_mem());
	if (!mem_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new mem_bio");
		goto err;
	}

	b64_bio = BIO_push(b64_bio, mem_bio);

	if (SIZE_MAX > INT_MAX && in->len > INT_MAX) {
		VANESSA_LOGGER_DEBUG("input is too long");
		goto err;
	}
	ilen = (int)in->len;

	if (BIO_write(b64_bio, in->data, ilen) != ilen) {
		VANESSA_LOGGER_DEBUG("BIO_write");
		goto err;
	}

	if (BIO_flush(b64_bio) != 1) {
		VANESSA_LOGGER_DEBUG("BIO_flush");
		goto err;
	}

	b64_len = BIO_get_mem_data(b64_bio, &b64_data);
	if (LONG_MAX > SIZE_MAX && b64_len > SIZE_MAX) {
		VANESSA_LOGGER_DEBUG("output is too long");
		goto err;
	}
	out.len = b64_len;

	out.data = malloc(out.len);
	if (!out.data) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		goto err;
	}

	memcpy(out.data, b64_data, out.len);
	base64_encode_clean(&out);

err:
	if (!out.data)
		buf_zero(&out);
	if (b64_bio)
		BIO_free_all(b64_bio);
	return out;
}

#define MIN(x, y) (x < y ? x : y)

static struct buf base64_decode_clean(const struct const_buf *in)
{
	STRUCT_BUF(out);
	int i;
	size_t o;

	/* As per RFC2045 the maximum encoded line length is 76,
	 * the line separator is "\r\n" and
	 * the encoded text must end with a line separator
	 */
	out.len = in->len + ((in->len / 76) + 1) * 2;

	/* Overflow */
	if (in->len > out.len) {
		VANESSA_LOGGER_DEBUG("string is too long");
		goto err;
	}

	out.data = malloc(out.len);
	if (!out.data) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		goto err;
	}

	for (i = o = 0; o < out.len; i += 76, o += 78) {
		size_t copy_len = MIN(76, in->len - i);
		memcpy(out.data + o, in->data + i, copy_len);
		out.data[o + copy_len] = '\r';
		out.data[o + copy_len + 1] = '\n';
	}

err:
	if (!out.data)
		buf_zero(&out);
	return out;
}

/**********************************************************************
 * base64_decode
 * pre: in: struct buf to decode
 * return: on success: { .buf = str, .len = len }
 *         on invalid input: { .buf = NULL, .len = 1 }
 *         on any other error: { .buf = NULL, .len = 0 }
 *         buf_is_err() can be used to test for { .buf == NULL }
 **********************************************************************/

struct buf base64_decode(const struct const_buf *in)
{
	BIO *mem_bio = NULL, *b64_bio;
	int ilen, error = 1;
	STRUCT_BUF(out);
	STRUCT_BUF(clean);

	clean = base64_decode_clean(in);
	if (buf_is_err(&clean)) {
		VANESSA_LOGGER_DEBUG("base64_decode_clean");
		goto err;
	}

	if (SIZE_MAX > INT_MAX && clean.len > INT_MAX) {
		VANESSA_LOGGER_DEBUG("str is too long");
		goto err;
	}
	ilen = (int)clean.len;

	mem_bio = BIO_new_mem_buf(clean.data, ilen);
	if (!mem_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new mem_bio");
		goto err;
	}

	b64_bio = BIO_new(BIO_f_base64());
	if (!b64_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new b64_bio");
		goto err;
	}

	mem_bio = BIO_push(b64_bio, mem_bio);

	out.data = calloc(1, clean.len);
	if (!out.data) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		goto err;
	}

	ilen = BIO_read(mem_bio, out.data, ilen);
	if (ilen <= 0) {
		/* Assume that this is because the input string was
		 * invalid, which is not a fatal error */
		out.len = 1;
		goto err;
	}

	if (INT_MAX > SIZE_MAX && ilen > SIZE_MAX) {
		VANESSA_LOGGER_DEBUG("output is too long");
		goto err;
	}
	out.len = ilen;

	error = 0;
err:
	if (error) {
		free(out.data);
		buf_zero(&out);
	}
	if (mem_bio)
		BIO_free_all(mem_bio);
	free(clean.data);
	return out;
}
