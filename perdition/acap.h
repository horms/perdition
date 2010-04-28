#ifndef PERDITION_ACAP_H
#define PERDITION_ACAP_H

#include "perdition_types.h"

struct acap {
	char *a;
	const char *b;
};

#define STRUCT_ACAP(name) \
	struct acap (name) = { NULL, NULL }

static inline int acap_is_zero(struct acap *ac)
{
	return !ac->a && !ac->b;
}

void acap_free(struct acap *as);

struct acap acap_from_str(const char *str, flag_t flag);

#endif /* PERDITION_ACAP_H */
