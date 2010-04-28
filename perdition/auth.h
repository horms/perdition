#ifndef PERDITION_AUTH_H
#define PERDITION_AUTH_H

#include <string.h>
#include <stdlib.h>

struct auth {
	char *authorisation_id; /* Optional user to use the credentials of
				 * to access authentication_id's account.
				 * E.g. admin accessing a user's account */
	char *authentication_id;
	char *passwd;

	enum {
		auth_t_none = 0,
		auth_t_passwd,
		auth_t_sasl_plain
	} type;
};

#define STRUCT_AUTH(name) \
	struct auth (name) = { .type = auth_t_none }

static inline void auth_zero(struct auth *auth)
{
	memset(auth, 0, sizeof(auth));
}

static inline void auth_set_authorisation_id(struct auth *auth, char *id)
{
	if (auth->authorisation_id)
		auth->authorisation_id = id;
	else
		auth->authentication_id = id;
}

static inline char *auth_get_authorisation_id(const struct auth *auth)
{
	if (auth->authorisation_id)
		return auth->authorisation_id;
	return auth->authentication_id;
}

static inline void auth_free_data(const struct auth *auth)
{
	if (!auth)
		return;

	switch (auth->type) {
	case auth_t_none:
		return;
	case auth_t_passwd:
	case auth_t_sasl_plain:
		break;
	}

	free(auth->authorisation_id);
	free(auth->authentication_id);
	free(auth->passwd);
}

static inline struct auth auth_set_pwd(char *name, char *passwd)
{
	struct auth a = {
		.type = auth_t_passwd,
		.authentication_id = name,
		.passwd = passwd
	};

	return a;
}

static inline struct auth auth_set_sasl_plain(char *authorisation_id,
					      char *authentication_id,
					      char *passwd)
{
	struct auth a = {
		.type = auth_t_sasl_plain,
		.authorisation_id = authorisation_id,
		.authentication_id = authentication_id,
		.passwd = passwd
	};

	return a;
}

#endif /* PERDITION_AUTH_H */
