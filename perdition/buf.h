#ifndef PERDITION_BUF_H
#define PERDITION_BUF_H

#include <stdlib.h>
#include <string.h>

struct const_buf {
	size_t len;
	const char *data;
};

#define STRUCT_CONST_BUF(name) \
	struct const_buf name = { 0, NULL }

struct buf {
	size_t len;
	char *data;
};

#define STRUCT_BUF(name) \
	struct buf name = { 0, NULL }

static inline void buf_zero(struct buf *b)
{
	memset(b, 0, sizeof(*b));
}

static inline int buf_is_err(struct buf *b)
{
	return b->data == NULL;
}

/**********************************************************************
 * buf_dup_from_const
 * pre: in: struct const_buf to duplicate
 * return: on success: { .buf = str, .len = len }
 *         on error: { .buf = NULL, .len = 0 }
 *         buf_is_err() can be used to test for { .buf == NULL }
 **********************************************************************/

static inline struct buf buf_dup_from_const(const struct const_buf *src)
{
	STRUCT_BUF(dst);

	dst.data = malloc(src->len);
	if (dst.data) {
		memcpy(dst.data, src->data, src->len);
		dst.len = src->len;
	}

	return dst;
}

#endif /* PERDITION_BUF_H */

