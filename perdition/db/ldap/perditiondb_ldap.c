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
 * Copyright (C) 2000-2001  ChrisS and Horms
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

#ifdef HAVE_PARSE_PRINTF_FORMAT
#include <printf.h>
#endif 

#ifdef DMALLOC
#include <dmalloc.h>
#endif


static LDAPURLDesc *ludp;

/**********************************************************************
 * perditiondb_ldap_vanessa_socket_str_is_digit
 * Test if a null terminated string is composed entirely of digits (0-9)
 *
 * Code borrowed from ../../str.c
 *
 * pre: str
 * return: 1 if string contains only digits and null teminator
 *         0 otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

static int perditiondb_ldap_vanessa_socket_str_is_digit(const char *str){
  size_t offset;
  size_t top;

  top=strlen(str);
  for(offset=0;offset<strlen(str);offset++){
    /*Is digit on solaris appears to be broken and expect an int as
      the argument, a typecast should aviod a compiler warning */
    if(!isdigit((int)*(str+offset))){
      break;
    }
  }

  return((offset<top)?0:1);
}


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

int dbserver_init(char *options_str) {
#ifdef HAVE_PARSE_PRINTF_FORMAT
  int arg_type;
#endif

  if (options_str == NULL) {
    options_str=PERDITIONDB_LDAP_DEFAULT_URL;
  }

  /*
   * Some checks to see if the URL is sane in LDAP terms
   */
  if (ldap_is_ldap_url(options_str) == 0) {
    PERDITION_DEBUG("not an LDAP URL");
    return(-1);
  }
  if (ldap_url_parse(options_str, &ludp) != 0) {
    PERDITION_DEBUG("ldap_url_parse");
    return(-1);
  }

#ifdef HAVE_PARSE_PRINTF_FORMAT
  /*
   * Some checks to protect against format problems
   */
  if(parse_printf_format(ludp->lud_filter, 1, &arg_type) != 1){
    PERDITION_DEBUG("LDAP URL has more than one format flag");
    return(-1);
  }
  if((arg_type & ~PA_FLAG_MASK) != PA_STRING){
    PERDITION_DEBUG("LDAP URL has a non-string format flag");
    return(-1);
  }
  if((arg_type & PA_FLAG_MASK)){
    PERDITION_DEBUG("LDAP URL has a modifier on format flag");
    return(-1);
  }
#endif /* HAVE_PARSE_PRINTF_FORMAT */

  return(0);
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

int dbserver_fini(void) {
  ldap_free_urldesc(ludp);
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

int dbserver_get(
  char *key_str, 
  char *options_str,
  char **str_return, 
  int  *len_return
){
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
  char critical;
  char *binddn=NULL;
  char *bindpw=NULL;

  extern options_t opt;

  *len_return = 0;

#ifdef WITH_LDAP_LUD_EXTS
  /* Scan through the extension list for anything interesting */
  count = 0;

  if (ludp->lud_exts != NULL) {
    while ((pstr = ludp->lud_exts[count]) != '\0')
    {
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
        binddn = pstr + 9;
      }
      else if (strncasecmp(pstr, "X-BINDPW", 8) == 0) {
        bindpw = pstr + 9;
      }
      else {
        /* Unknown extension */
        if (critical) {
          /* If critical RFC2255 says we have to abort */
          PERDITION_INFO_UNSAFE("Critical extension, %s unsupported", pstr);
          goto leave;
        }
        else {
          /* Not critical, we just ignore it */
        }
      }

      count++;
    }
  }
#else /* WITH_LDAP_LUD_EXTS */
  critical = 0; /* Keep the compiler quiet */
#endif /* WITH_LDAP_LUD_EXTS */

  /* Open LDAP connection */
  if ((connection = ldap_open(ludp->lud_host, ludp->lud_port)) == NULL){
    PERDITION_DEBUG("ldap_open");
    goto leave;
  }
  if (ldap_bind_s(connection, binddn, bindpw, LDAP_AUTH_SIMPLE) 
      != LDAP_SUCCESS){
    goto leave;
  }

  /* Build a filter string */
  if ((filter = (char *)malloc(strlen(key_str) +
       strlen(ludp->lud_filter))) == NULL) {
    PERDITION_DEBUG_ERRNO("filter malloc");
    status = -3;
    goto leave;
  }
  sprintf(filter, ludp->lud_filter, key_str);

  /* Perform the search */
  if ((ldap_search_s(connection, ludp->lud_dn, ludp->lud_scope,
       filter, ludp->lud_attrs, 0, &res)) != LDAP_SUCCESS) {
    PERDITION_DEBUG_ERRNO("ldap_search_s");
    goto leave;
  }
  free(filter);
  filter = NULL;

  /* See what we got back - we only bother with the first entry */
  if ((mptr = ldap_first_entry(connection, res)) == NULL) {
    PERDITION_DEBUG("ldap_first_entry");
    status = -2;
    goto leave;
  }

  /* See how many attributes we got */
  for (attrcount = 0; ludp->lud_attrs[attrcount] != NULL; attrcount++);

  /* Store the attributes somewhere */
  if ((ldap_returns = (char **)malloc(attrcount * sizeof(char *))) == NULL) {
    PERDITION_DEBUG_ERRNO("ldap_returns malloc");
    status = -3;
    goto leave;
  }
  memset(ldap_returns, 0, attrcount * sizeof(char *));

  *len_return = 0;
  for (pstr = ldap_first_attribute(connection, mptr, &ber); pstr != NULL;
       pstr = ldap_next_attribute(connection, mptr, ber)){
    bv_val = ldap_get_values(connection, mptr, pstr);

    for (count = 0; count < attrcount; count++) {
      if (strcasecmp(ludp->lud_attrs[count], pstr) == 0) {
        *len_return += strlen(*bv_val);
	if(ldap_returns[count] != NULL) {
		free(ldap_returns[count]);
	}
        if ((ldap_returns[count] = (char *)malloc(strlen(*bv_val)+1)) == NULL) {
          ldap_value_free(bv_val);
          ldap_memfree(pstr);
	  status = -3;
	  goto leave;
        }
        strcpy(ldap_returns[count], *bv_val);
      }
    }

    ldap_value_free(bv_val);
    ldap_memfree(pstr);
  }

  ber_free(ber, 0);
  ber = NULL;

  /* Add in some extra for the separators and terminating NULL */
  *len_return += attrcount;

  if ((*str_return = (char *)malloc(*len_return)) == NULL){
    PERDITION_DEBUG_ERRNO("str_return malloc");
    status = -3;
    goto leave;
  }

  /* Build the return string */
  strcpy(*str_return, ldap_returns[0]);
  free(ldap_returns[0]);
  ldap_returns[0] = NULL;
  for (count = 1; count < attrcount; count++) {
    if (ldap_returns[count] != NULL) {
      if (perditiondb_ldap_vanessa_socket_str_is_digit(ldap_returns[count])) {
        strcat(*str_return, ":");
      }
      else {
        strcat(*str_return, opt.domain_delimiter); 
      }
      strcat(*str_return, ldap_returns[count]);
      free(ldap_returns[count]);
      ldap_returns[count] = NULL;
    }
  }

  status = 0;

leave:
  if(filter != NULL)
    free(filter);
  if(ldap_returns != NULL) {
    for(count = 0; count < attrcount; count++)
      if(ldap_returns[count] != NULL)
        free(ldap_returns[count]);
    free(ldap_returns);
  }
  if(ber != NULL)
    ber_free(ber, 0);
  if(res != NULL)
    ldap_msgfree(res);
  if(connection != NULL)
    ldap_unbind_s(connection);

  return(status);
}
