#ifndef PERDITION_SOCK_H
#define PERDITION_SOCK_H

#include <sys/socket.h>

static size_t perdition_get_salen(const struct sockaddr *sa)
{
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	return sa->sa_len;
#else
	if (sa->sa_family == AF_INET)
		return sizeof(struct sockaddr_in);
	else
		return sizeof(struct sockaddr_in6);
#endif
}

#endif
