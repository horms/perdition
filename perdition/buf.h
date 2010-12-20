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

#endif /* PERDITION_BUF_H */

