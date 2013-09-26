#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

#include "log.h"
#include "buf.h"

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

	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

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

err:
	if (!out.data)
		buf_zero(&out);
	if (b64_bio)
		BIO_free_all(b64_bio);
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
	STRUCT_BUF(dup);

	/* This is necessary because BIO_new_mem_buf takes
	 * a non-const first argument */
	dup = buf_dup_from_const(in);
	if (buf_is_err(&dup)) {
		VANESSA_LOGGER_DEBUG("buf_dup_from_const");
		goto err;
	}

	if (SIZE_MAX > INT_MAX && dup.len > INT_MAX) {
		VANESSA_LOGGER_DEBUG("str is too long");
		goto err;
	}
	ilen = (int)dup.len;

	mem_bio = BIO_new_mem_buf(dup.data, dup.len);
	if (!mem_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new mem_bio");
		goto err;
	}

	b64_bio = BIO_new(BIO_f_base64());
	if (!b64_bio) {
		VANESSA_LOGGER_DEBUG("BIO_new b64_bio");
		goto err;
	}

	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
	mem_bio = BIO_push(b64_bio, mem_bio);

	out.data = calloc(1, dup.len);
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
	free(dup.data);
	return out;
}
