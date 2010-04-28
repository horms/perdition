#ifndef PERDITION_BASE64_H
#define PERDITION_BASE64_H

#include "buf.h"

/**********************************************************************
 * base64_decode
 * pre: in: struct buf to decode
 * return: on success: { .buf = str, .len = len }
 *         on error: { .buf = NULL, .len = 0 }
 *         buf_is_err() can be used to test for { .buf == NULL }
 **********************************************************************/

struct buf base64_encode(struct buf *in);

/**********************************************************************
 * base64_decode
 * pre: in: struct buf to decode
 * return: on success: { .buf = str, .len = len }
 *         on invalid input: { .buf = NULL, .len = 1 }
 *         on any other error: { .buf = NULL, .len = 0 }
 *         buf_is_err() can be used to test for { .buf == NULL }
 **********************************************************************/

struct buf base64_decode(struct buf *in);

#endif /* PERDITION_BASE64_H */
