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
 * Copyright (C) 1999-2002  ChrisS and Horms
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "perditiondb_ldap.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


static LDAPURLDesc *ludp;

static int ldap_version = PERDITIONDB_LDAP_VERSION;

/**********************************************************************
 * dbserver_init
 * Parse options string.
 * pre: options_str: Options string. Sting is the LDAP url to use
 *      see the default, PERDITIONDB_LDAP_DEFAULT_URL, for an example
 * post: Options string is parsed if not null into ludp
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_init(char *options_str)
{

	if (options_str == NULL) {
		options_str = PERDITIONDB_LDAP_DEFAULT_URL;
	}

	/*
	 * Some checks to see if the URL is sane in LDAP terms
	 */
	if (ldap_is_ldap_url(options_str) == 0) {
		VANESSA_LOGGER_DEBUG("not an LDAP URL");
		return (-1);
	}
	if (ldap_url_parse(options_str, &ludp) != 0) {
		VANESSA_LOGGER_DEBUG("ldap_url_parse");
		return (-1);
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
	ldap_free_urldesc(ludp);
	return (0);
}


/**********************************************************************
 * pldap_get_filter
 * returns filter array suitable for ldap search.  Be sure to free
 * returned string.
 * pre: filter_str contains LDAP search filter with '$' designating what
 *      needs to be replaced with key_str
 * post: returns filter
 * return:     NULL if error
 *             LDAP filter  on succes
 **********************************************************************/

static char *pldap_get_filter(const char *key_str, const char *filter_str)
{
	int i;
	int key_len;
	int filter_len;
	char c;
	char *return_filter;

	int format_percent = 0;
	const char *format_int = NULL;
	int format_width;

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
		c = filter_str[i];
		if (c == '%') {
			if(format_percent) {
				goto invalid;
			}
			format_percent++;
			continue;
		}
		if(format_percent && !format_int && isdigit((int)c)) {
			format_int = filter_str + i;
			continue;
		}
		if(format_percent && c == 's') {
			format_width = atoi(format_int);
			if(format_width < key_len) {
				format_width = key_len;
			}
			realloc(return_filter, filter_len + format_width);
			memmove(return_filter + i + format_width,
					return_filter + i, 
					filter_len - i);
			memset(return_filter + i, ' ', format_width);
			memcpy(return_filter + format_width - key_len,
					key_str, key_len);
			filter_len += format_width;

			format_percent = 0;
			format_int = NULL;
			continue;
		}
		if(format_percent) {
			goto invalid;
		}
	}

	return(return_filter);

invalid:
	VANESSA_LOGGER_DEBUG("invalid format");
	free(return_filter);
	return(NULL);

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


/**********************************************************************
 * dbserver_get
 * Read the server (value) from an LDAP directory given the user (key)
 * pre: key_str: Key as a null terminated string
 *      options_str: Options string. 
 *                   Ignored if NULL
 *                   Used as the map to open otherwise
 *      str_return: value is returned here
 *      len_return: length of value is returned here
 * post: The str_key is looked up in the gdbm map and the
 *       corresponding value is returned in str_return and len_return.
 * return:  0 on success
 *         -1 on LDAP access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_get(const char *key_str,
		 const char *options_str,
		 char **str_return, int *len_return)
{
	LDAP *connection = NULL;
	LDAPMessage *res = NULL;
	LDAPMessage *mptr = NULL;
	BerElement *ber = NULL;
	int count;
	int attrcount = 0;
	int status = -1;
	char *pstr;
	char **bv_val = NULL;
	char *filter = NULL;
	char **ldap_returns = NULL;
	char *binddn = NULL;
	char *bindpw = NULL;

	extern options_t opt;

	*len_return = 0;


	/* Open LDAP connection */
	connection = ldap_init(ludp->lud_host, ludp->lud_port);
	if (!connection) {
		VANESSA_LOGGER_DEBUG("ldap_init");
		goto leave;
	}

#ifdef WITH_LDAP_LUD_EXTS
	/* Check extensions */
	if(pldap_scan_exts(ludp->lud_exts, &binddn, &bindpw)) {
		VANESSA_LOGGER_DEBUG("ldap_scan_exts");
		goto leave;
	}
#endif /* WITH_LDAP_LUD_EXTS */

#ifdef LDAP_SET_OPTION
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
#endif /* LDAP_SET_OPTION */

#ifdef LDAP_SET_OPTION
	if(ldap_set_option(connection, LDAP_OPT_PROTOCOL_VERSION, 
				&ldap_version) != LDAP_OPT_SUCCESS ) {
		VANESSA_LOGGER_DEBUG("ldap_protocol_version");
		return(-1);
	}
#endif /* LDAP_SET_OPTION */

	if (ldap_bind_s(connection, binddn, bindpw, LDAP_AUTH_SIMPLE)
	    != LDAP_SUCCESS) {
		goto leave;
	}


	/* get filter string */
	if ((filter = pldap_get_filter(key_str, ludp->lud_filter)) == NULL) {
		VANESSA_LOGGER_DEBUG("get filter");
		status = -3;
		goto leave;
	}

	/* Perform the search */
	if ((ldap_search_s(connection, ludp->lud_dn, ludp->lud_scope,
			   filter, ludp->lud_attrs, 0,
			   &res)) != LDAP_SUCCESS) {
		VANESSA_LOGGER_DEBUG_ERRNO("ldap_search_s");
		goto leave;
	}

	/* Warn about multiple entries being returned */
	if (ldap_count_entries(connection, res) > 1) {
		VANESSA_LOGGER_LOG_UNSAFE(LOG_WARNING, 
				"multiple entries returned by filter: "
				"base: %s; scope: %s; filter: %s", 
				ludp->lud_dn, ludp->lud_scope, filter);
	}

	free(filter);
	filter = NULL;

	/* See what we got back - we only bother with the first entry */
	if ((mptr = ldap_first_entry(connection, res)) == NULL) {
		VANESSA_LOGGER_DEBUG("ldap_first_entry");
		status = -2;
		goto leave;
	}

	/* See how many attributes we got */
	for (attrcount = 0; ludp->lud_attrs[attrcount] != NULL;
	     attrcount++);

	/* Store the attributes somewhere */
	if ((ldap_returns =
	     (char **) malloc(attrcount * sizeof(char *))) == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("ldap_returns malloc");
		status = -3;
		goto leave;
	}
	memset(ldap_returns, 0, attrcount * sizeof(char *));

	*len_return = 0;
	for (pstr = ldap_first_attribute(connection, mptr, &ber);
	     pstr != NULL;
	     pstr = ldap_next_attribute(connection, mptr, ber)) {
		bv_val = ldap_get_values(connection, mptr, pstr);

		for (count = 0; count < attrcount; count++) {
			if (strcasecmp(ludp->lud_attrs[count], pstr) != 0) {
				continue;
			}
			*len_return += strlen(*bv_val);
			if (ldap_returns[count] != NULL) {
				free(ldap_returns[count]);
			}
			ldap_returns[count] = (char *) malloc(strlen(*bv_val) 
					+ 1);
			if(!ldap_returns[count]) {
				ldap_value_free(bv_val);
				ldap_memfree(pstr);
				status = -3;
				goto leave;
			}
			strcpy(ldap_returns[count], *bv_val);
			break;
		}

		ldap_value_free(bv_val);
		ldap_memfree(pstr);
	}

	ber_free(ber, 0);
	ber = NULL;

	/* Add in some extra for the separators and terminating NULL */
	*len_return += attrcount;

	if ((*str_return = (char *) malloc(*len_return)) == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("str_return malloc");
		status = -3;
		goto leave;
	}

	/* Build the return string */
	strcpy(*str_return, ldap_returns[0]);
	free(ldap_returns[0]);
	ldap_returns[0] = NULL;
	for (count = 1; count < attrcount; count++) {
		if (ldap_returns[count] != NULL) {
			if (vanessa_socket_str_is_digit(ldap_returns[count])) {
				strcat(*str_return, ":");
			} else {
				strcat(*str_return, opt.domain_delimiter);
			}
			strcat(*str_return, ldap_returns[count]);
			free(ldap_returns[count]);
			ldap_returns[count] = NULL;
		}
	}

	/* If there is no opt.domain_delimiter present in *str_return,
	 * then no servername has been found and the result is useless */
	if (strstr(*str_return, opt.domain_delimiter) == NULL) {
		free(*str_return);
		status = -1;
	} else {
		status = 0;
	}

      leave:
	if (filter != NULL)
		free(filter);
	if (ldap_returns != NULL) {
		for (count = 0; count < attrcount; count++)
			if (ldap_returns[count] != NULL)
				free(ldap_returns[count]);
		free(ldap_returns);
	}
	if (ber != NULL)
		ber_free(ber, 0);
	if (res != NULL)
		ldap_msgfree(res);
	if (connection != NULL)
		ldap_unbind_s(connection);

	return (status);
}
