/**********************************************************************
 * perditiondb_ldap.c                                        April 2000
 * ChrisS                                              chriss@uk.uu.net
 *
 * Access an LDAP database
 * The LDAP search URL shuld be in *options_str with the required
 * attributes in the following order:
 *  new username (optional)
 *  server
 *  port (optional)
 *
 * perdition
 * Mail retrieval proxy server, LDAP support
 * Copyright (C) 1999-2005  ChrisS and Horms
 * 
 * Contributions:
 *
 *
 * 	Oct/2007: Confederacao SICREDI - www.sicredi.com.br
 *                Felipe Damasio - felipe_damasio@sicredi.com.br
 *                Tiago A. Wegner - tiago_wegner@sicredi.com.br
 * 	- Fix the LDAP connection using the proper string for ldap_initialize
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "perdition_globals.h"
#include "perditiondb_ldap.h"
#include "unused.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

static char *pldap_filter = NULL;

static int pldap_version = PERDITIONDB_LDAP_VERSION;

/**********************************************************************
 * dbserver_init
 * Parse options string.
 * pre: options_str: Options string. Sting is the LDAP url to use
 *      see the default, PERDITIONDB_LDAP_DEFAULT_URL, for an example
 * post: Options string is parsed if not null into lud
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_init(char *options_str)
{
	char *str = options_str;

	if (str && *str) {
		if (*(str+1) == '\0') {
			pldap_version = (int) *str - '0';
			str++;
		}
		else if (*(str+1) == ':') {
			pldap_version = (int) *str - '0';
			str += 2;
		}
	}

	if (pldap_version < LDAP_VERSION_MIN || 
			pldap_version > LDAP_VERSION_MAX) {
		VANESSA_LOGGER_DEBUG_RAW_UNSAFE("Requested ldap version (%c): "
				"is out of range. Must be a numeric value "
				"between %d and %d", *options_str, 
				LDAP_VERSION_MIN, LDAP_VERSION_MAX);
		return -1;
	}

#ifdef WITH_LDAP_SET_OPTION
	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("Using LDAP version: %d", 
			pldap_version);
#else
	VANESSA_LOGGER_DEBUG_RAW_UNSAFE(
			"The ldap library perdition was compiled against "
			"does not support setting of the ldap version. "
			"Using the default version: %d", LDAP_VERSION);
#endif

	if (!str || !*str) {
		str = PERDITIONDB_LDAP_DEFAULT_URL;
	}

	/*
	 * Some checks to see if the URL is sane in LDAP terms
	 */
	if (ldap_is_ldap_url(str) == 0) {
		VANESSA_LOGGER_DEBUG("ldap_is_ldap_url: not an LDAP URL");
		return (-1);
	}

	pldap_filter = strdup(str);
	if(!pldap_filter) {
		VANESSA_LOGGER_DEBUG_ERRNO("pldap_filter");
	}

	return (0);
}

/**********************************************************************
 * dbserver_fini
 * Free static vanessa_dynamic_array_t a if it has been initialised
 * pre: none
 * post: static vanessa_dynamic_array_t a and its contents are freed
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_fini(void)
{
	if(pldap_filter) {
		free(pldap_filter);
		pldap_filter=NULL;
	}
	return (0);
}


/**********************************************************************
 * pldap_get_filter_str
 * returns filter string suitable for ldap search.  Be sure to free
 * returned string.
 * pre: filter_str contains LDAP search filter with '$' designating what
 *      needs to be replaced with key_str
 * post: returns filter
 * return:     NULL if error
 *             LDAP filter  on succes
 **********************************************************************/

static char *pldap_get_filter_str(const char *key_str, const char *filter_str)
{
	int i;
	int key_len;
	int filter_len;
	char c;
	char *return_filter;

	int format_percent = 0;
	int format_int = 0;
	int format_width;
	int dead_width;

	key_len = strlen(key_str);
	filter_len = strlen(filter_str);

	/* allocate space for filter */
	return_filter = strdup(filter_str);
	if (!return_filter) {
		VANESSA_LOGGER_DEBUG_ERRNO("strdup");
		return NULL;
	}

	/* find number of subs to make */
	for (i = 0; i < filter_len; i++) {
		c = return_filter[i];
		if (c == '%') {
			format_percent ^= 1;
			continue;
		}
		if(format_percent && isdigit((int)c)) {
			if(!format_int) {
				format_int = i;
			}
			continue;
		}
		if(format_percent && c == 's') {
			if(format_int) {
				format_width = atoi(return_filter+format_int);
				dead_width = i - format_int + 2;
				i = format_int - 1;
			}
			else {
				format_width = 0;
				dead_width = 2;
				i--;
			}
			if(format_width < key_len) {
				format_width = key_len;
			}

			return_filter = realloc(return_filter, filter_len + 
					format_width - dead_width + 1);
			if(!return_filter) {
				VANESSA_LOGGER_DEBUG_ERRNO("realloc");
				return(NULL);
			}

			memmove(return_filter + i + format_width,
					return_filter + i + dead_width,
					filter_len - i - dead_width);
			memset(return_filter + i, ' ', format_width);  
			memcpy(return_filter + i + format_width - key_len,
					key_str, key_len);
			filter_len += format_width - dead_width;
			*(return_filter + filter_len) = '\0'; 
			i += format_width - 1;
		}
		format_percent = 0;
		format_int = 0;
	}

	return(return_filter);
}


static int pldap_get_filter(const char *key_str, const char *filter_str,
		LDAPURLDesc    **lud)
{
	int err;
	char *new_filter;

	new_filter = pldap_get_filter_str(key_str, filter_str);
	if(!new_filter) {
		VANESSA_LOGGER_DEBUG("pldap_get_filter_str");
		return(-1);
	}

	err = ldap_url_parse(new_filter, lud);
	if (err) {
		VANESSA_LOGGER_DEBUG_UNSAFE("ldap_url_parse: %s",
				ldap_err2string(err));
		free(new_filter);
		return (-1);
	}

	free(new_filter);
	return(0);
}

/**********************************************************************
 * pldap_scan_exts
 * Scan an array of ldap extensions returned from an ldap
 * query. 
 *
 * pre: exts: array of ldap extensions
 *      bindname: pointer to stor BINDNAME, if found
 *      xbindpw: pointer to stor X-BINDPW, if found
 * post: bindname is filled in if it was found, NULL otherwise
 *       xbindwp is filled in if it was found, NULL otherwise
 * return: 1 if an extension other than BINDNAME or X-BINDPW
 *         was specified and marked as critical.
 *         0 otherwise
 **********************************************************************/

static int pldap_scan_exts(char **exts, char **bindname, char **xbindpw)
{
	size_t count;
	int critical;
	char *pstr;

	/* Scan through the extension list for anything interesting */
	count = 0;

	if (exts == NULL) {
		return(0);
	}

	*bindname = NULL;
	*xbindpw = NULL;

	while ((pstr = exts[count]) != '\0') {
		count++;

		/* Check critical status */
		if (*pstr == '!') {
			critical = 1;
			pstr++;
		} 
		else {
			critical = 0;
		}

		/* Check for extensions */
		if (strncasecmp(pstr, "BINDNAME", 8) == 0) {
			*bindname = pstr + 9;
			continue;
		} 
		else if (strncasecmp(pstr, "X-BINDPW", 8) == 0) {
			*xbindpw = pstr + 9;
			continue;
		} 

		/* Unknown extension */
		if (critical) {
			/* If critical RFC2255 says we have to abort */
			VANESSA_LOGGER_INFO_UNSAFE(
					"Critical extension, %s unsupported", 
					pstr);
			return(1);
		} 
	}

	return(0);
}

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static char *perdition_ldap_uri (const LDAPURLDesc *lud)
{
	int nhost = 1;
	char *uri, *start, *end;

	/* Multiple hosts may be supplied, space delimited.
	 * But they will all end up with the same port.
	 * This is supported by openldap.
	 * The location of the specification for this is as yet unknown. */

	start = lud->lud_host;
	while (*start == ' ')
		start++;
	while ((start = strchr(start, ' '))) {
		nhost++;
		while (*start == ' ')
			start++;
	}

	/*
         * The '+9' on calloc is the worst case scenario of a non-default
         * LDAP port: 65535 and such. The extra bytes are for the leading
	 * "://" and trailing ' ' or '\n'.
         */
	uri = calloc((strlen(lud->lud_scheme) + 9) * nhost +
		     strlen(lud->lud_host) + 1, 1);
	if (!uri)
		return NULL;

	start = lud->lud_host;
	do {
		while (*start == ' ')
			start++;
		end = strchr(start, ' ');
		if (!end)
			end = start + strlen(start);

		if (end == start)
			break;

		if (*uri)
			strcat(uri, " ");
		strcat(uri, lud->lud_scheme);
		strcat(uri, "://");
		strncat(uri, start, end - start);
		if (lud->lud_port != LDAP_PORT) {
			strcat(uri, ":");
			sprintf(uri + strlen(uri),
				"%d", lud->lud_port);
		}
	} while ((start = strchr(start, ' ')));

	return uri;
}

static LDAP *perdition_ldap_initialize (const LDAPURLDesc *lud)
{
	int err;
	char *uri;
	LDAP *connection = NULL;

	uri = perdition_ldap_uri(lud);
	if (uri == NULL) {
		VANESSA_LOGGER_DEBUG("perdition_ldap_uri");
		return NULL;
	}

	err = ldap_initialize(&connection, uri);
	if (err != LDAP_SUCCESS) {
		VANESSA_LOGGER_DEBUG_UNSAFE("ldap_initialize: %s", uri);
		VANESSA_LOGGER_DEBUG_UNSAFE("ldap_initialize: %s",
				ldap_err2string(err));
		connection = NULL;
		goto leave;
	}

leave:
	free(uri);
	return connection;
}
#else
static LDAP *perdition_ldap_initialize (const LDAPURLDesc *lud)
{
	LDAP *connection;

	connection = ldap_init(lud->lud_host, lud->lud_port);

	if (!connection) {
		VANESSA_LOGGER_DEBUG_ERRNO("ldap_init");
		return NULL;
	}

	return connection;
}
#endif

/**********************************************************************
 * dbserver_get2
 * Read the server (value) from an LDAP directory given the user (key)
 * pre: key_str: Key as a null terminated string
 *      options_str: Options string.
 *                   Ignored if NULL
 *                   Used as the map to open otherwise
 *      user_str: string for user is returned here
 *      server_str: string for server is returned here
 *      port_str: string for port is returned here
 * post: The str_key is looked up in the ldap database and the
 *       corresponding values are returned in user_str, server_str and
 *       port_str.
 * return:  0 on success
 *         -1 on LDAP access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_get2(const char *key_str, const char *UNUSED(options_str),
		 char **user_str, char **server_str, char **port_str)
{
	LDAPURLDesc *lud = NULL;
	LDAP *connection = NULL;
	LDAPMessage *res = NULL;
	LDAPMessage *mptr = NULL;
	BerElement *ber = NULL;
	int count;
	int attrcount = 0;
	int status = -1;
	int err;
	char *pstr;
	char **bv_val = NULL;
	char **returns = NULL;
	char *binddn = NULL;
	char *bindpw = NULL;

	/* get filter string */
	if (pldap_get_filter(key_str, pldap_filter, &lud) < 0) {
		VANESSA_LOGGER_DEBUG("pldap_get_filter");
		lud = NULL;
		status = -3;
		goto leave;
	}

	/* Open LDAP connection */
	connection = perdition_ldap_initialize(lud);
	if (!connection) {
		VANESSA_LOGGER_DEBUG("perdition_ldap_initialize");
		goto leave;
	}

#ifdef WITH_LDAP_LUD_EXTS
	/* Check extensions */
	if(pldap_scan_exts(lud->lud_exts, &binddn, &bindpw)) {
		VANESSA_LOGGER_DEBUG("ldap_scan_exts");
		goto leave;
	}
#endif /* WITH_LDAP_LUD_EXTS */

#ifdef WITH_LDAP_SET_OPTION
#ifdef LDAP_OPT_NETWORK_TIMEOUT
	{
		struct timeval mytimeval;
		mytimeval.tv_sec = 10;
		mytimeval.tv_usec = 0;
		if (ldap_set_option(connection, LDAP_OPT_NETWORK_TIMEOUT,
				    &mytimeval) != LDAP_OPT_SUCCESS) {
			VANESSA_LOGGER_DEBUG("ldap_network_timeout");
			return (-1);
		}
	}
#endif /* LDAP_OPT_NETWORK_TIMEOUT */

	err = ldap_set_option(connection, LDAP_OPT_PROTOCOL_VERSION, 
				&pldap_version);
	if(err != LDAP_SUCCESS) {
		VANESSA_LOGGER_DEBUG_UNSAFE("ldap_protocol_version: %s: %s",
				ldap_err2string(err), strerror(errno));
		return(-1);
	}
#endif /* WITH_LDAP_SET_OPTION */

	err = ldap_bind_s(connection, binddn, bindpw, LDAP_AUTH_SIMPLE);
	if (err != LDAP_SUCCESS) {
		VANESSA_LOGGER_DEBUG_UNSAFE("ldap_bind_s: %s", 
				ldap_err2string(err));
		goto leave;
	}



	/* Perform the search */
	err = ldap_search_s(connection, lud->lud_dn, lud->lud_scope,
			   lud->lud_filter, lud->lud_attrs, 0, &res);
        /* Simon Fraser has observed that when using openldap 2.4.11 on
	 * Debian Etch (2.1.30) that ldap_search_s() may return
	 * LDAP_SERVER_DOWN even if the search is successful.
	 */
	if (err != LDAP_SUCCESS && err != LDAP_SERVER_DOWN) {
		VANESSA_LOGGER_DEBUG_UNSAFE("ldap_search_s: %s",
				ldap_err2string(err));
		goto leave;
	}

	/* Warn about multiple entries being returned */
	err = ldap_count_entries(connection, res);
	if(err < 0) {
		VANESSA_LOGGER_DEBUG_UNSAFE("ldap_count_entries: %s",
				ldap_err2string(err));
		goto leave;
	}
	if (err > 1) {
		VANESSA_LOGGER_LOG_UNSAFE(LOG_WARNING, 
				"multiple entries returned by filter: "
				"base: %s; scope: %s; filter: %s", 
				lud->lud_dn, lud->lud_scope, lud->lud_filter);
	}

	/* See what we got back - we only bother with the first entry */
	if ((mptr = ldap_first_entry(connection, res)) == NULL) {
		VANESSA_LOGGER_DEBUG("ldap_first_entry");
		status = -2;
		goto leave;
	}

	/* See how many attributes we got */
	for (attrcount = 0; 
	     lud->lud_attrs[attrcount] != NULL && attrcount < 3; attrcount++);

	/* Store the attributes somewhere */
	returns = (char **) calloc(attrcount, sizeof(char *));
	if (!returns) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc ldap_returns");
		status = -3;
		goto leave;
	}

	for (pstr = ldap_first_attribute(connection, mptr, &ber);
	     pstr != NULL;
	     pstr = ldap_next_attribute(connection, mptr, ber)) {
		bv_val = ldap_get_values(connection, mptr, pstr);

		for (count = 0; count < attrcount; count++) {
			if (strcasecmp(lud->lud_attrs[count], pstr) != 0) {
				continue;
			}
			if (returns[count] != NULL) {
				free(returns[count]);
			}
			returns[count] = (char *) malloc(strlen(*bv_val) + 1);
			if(!returns[count]) {
				VANESSA_LOGGER_DEBUG_ERRNO("malloc");
				ldap_value_free(bv_val);
				ldap_memfree(pstr);
				status = -3;
				goto leave;
			}
			strcpy(returns[count], *bv_val);
			break;
		}

		ldap_value_free(bv_val);
		ldap_memfree(pstr);
	}

	ber_free(ber, 0);
	ber = NULL;

	/* Build the return string */
	if (returns[0] && !returns[1] && !returns[2]) {
		user_server_port_t *usp = NULL;
		if (user_server_port_str_assign(&usp, returns[0]) < 0) {
			VANESSA_LOGGER_DEBUG("user_server_port_str_assign");
			goto leave;
		}
		free(returns[0]);
		*user_str = user_server_port_get_user(usp);
		*server_str = user_server_port_get_server(usp);
		*port_str = user_server_port_get_port(usp);
		user_server_port_unassign(usp);
		user_server_port_destroy(usp);
	}
	else {
		if (returns[0])
			*user_str = returns[0];
		if (returns[1])
			*server_str = returns[1];
		if (returns[2])
			*port_str = returns[2];
	}

	status = 0;

      leave:
	if (returns && status) {
		for (count = 0; count < attrcount; count++)
			if (returns[count] != NULL)
				free(returns[count]);
		free(returns);
	}
	if (ber)
		ber_free(ber, 0);
	if (res)
		ldap_msgfree(res);
	if (connection) {
		ldap_unbind_s(connection);
	}
	if(lud) {
		ldap_free_urldesc(lud);
	}

	return (status);
}
