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

#include "perditiondb_ldap.h"

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
  extern options_t opt;
  char *tmpstr;
  char *ptr;
  int count;
  int found;

  if (options_str == NULL) {
    options_str=PERDITIONDB_LDAP_DEFAULT_URL;
  }

  /* Convert "%" to "%25" to keep the ldap_url_parse code happy */
  found = 0;

  /* See how many % characters there are */
  /* (hopefully only 1, but we might as well do this properly) */
  for (count = 0; count < strlen(options_str); count++) {
    if (options_str[count] == '%') {
      found++;
    }
  }

  if ((tmpstr = malloc(strlen(options_str) + (found * 2) + 1)) == NULL) {
    if (opt.debug) {
      fprintf(stderr, "dbserver_init: malloc\n");
    }
    PERDITION_LOG(LOG_DEBUG, "dbserver_init: malloc");
    return(-1);
  }

  ptr = tmpstr;
  /* Copy the string, expanding as we go */
  for (count = 0; count < strlen(options_str); count++) {
    *ptr++ = options_str[count];
    if (options_str[count] == '%') {
      *ptr++ = '2';
      *ptr++ = '5';
    }
  }
  *ptr = '\0';

  if (ldap_is_ldap_url(options_str) == 0) {
    if(opt.debug){
      fprintf(stderr, "dbserver_init: not an LDAP URL\n");
    }
    PERDITION_LOG(LOG_DEBUG, "dbserver_init: not an LDAP URL");
    free(tmpstr);
    return(-1);
  }

  if (ldap_url_parse(tmpstr, &ludp) != 0) {
    if(opt.debug){
      fprintf(stderr, "dbserver_init: ldap_url_parse\n");
    }
    PERDITION_LOG(LOG_DEBUG, "dbserver_init: ldap_url_parse");
    free(tmpstr);
    return(-1);
  }

  free(tmpstr);
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
  LDAP *connection;
  LDAPMessage *res;
  LDAPMessage *mptr;
  BerElement *ber;
  int msgid;
  int count;
  int attrcount;
  char *pstr;
  char **bv_val=NULL;
  char *filter;
  char **ldap_returns;

  extern options_t opt;

  *len_return = 0;

  /* Open LDAP connection */
  if ((connection = ldap_open(ludp->lud_host, ludp->lud_port)) == NULL){
    PERDITION_LOG(LOG_DEBUG, "db_server_get: ldap_open");
    return(-1);
  }
  if ((msgid = ldap_bind_s(connection, NULL, NULL,
       LDAP_AUTH_SIMPLE)) != LDAP_SUCCESS){
    PERDITION_LOG(LOG_DEBUG, "db_server_get: ldap_bind");
    return(-1);
  }

  /* Build a filter string */
  if ((filter = (char *)malloc(strlen(key_str) +
       strlen(ludp->lud_filter))) == NULL) {
    PERDITION_LOG(LOG_DEBUG, "db_server_get: filter malloc");
    ldap_unbind_s(connection);
    return(-3);
  }
  sprintf(filter, ludp->lud_filter, key_str);

  /* Perform the search */
  if ((ldap_search_s(connection, ludp->lud_dn, ludp->lud_scope,
       filter, ludp->lud_attrs, 0, &res)) != LDAP_SUCCESS) {
    free(filter);
    ldap_unbind_s(connection);
    return(-1);
  }
  free(filter);

  /* See what we got back - we only bother with the first entry */
  if ((mptr = ldap_first_entry(connection, res)) == NULL) {
    PERDITION_LOG(LOG_DEBUG, "db_server_get: ldap_first_entry");
    ldap_unbind_s(connection);
    return(-2);
  }

  /* See how many attributes we got */
  for (attrcount = 0; ludp->lud_attrs[attrcount] != NULL; attrcount++);

  /* Store the attributes somewhere */
  if ((ldap_returns = (char **)malloc(attrcount * sizeof(char *))) == NULL) {
    PERDITION_LOG(LOG_DEBUG, "db_server_get: ldap_returns malloc");
    ldap_unbind_s(connection);
    return(-3);
  }

  for (count = 0; count < attrcount; count++) {
    ldap_returns[count] = NULL;
  }

  *len_return = 0;
  for (pstr = ldap_first_attribute(connection, mptr, &ber); pstr != NULL;
       pstr = ldap_next_attribute(connection, mptr, ber)){
    bv_val = ldap_get_values(connection, mptr, pstr);

    for (count = 0; count < attrcount; count++) {
      if (strcasecmp(ludp->lud_attrs[count], pstr) == 0) {
        *len_return += strlen(*bv_val);
        if ((ldap_returns[count] = (char *)malloc(strlen(*bv_val)+1)) == NULL) {
          ldap_value_free(bv_val);
          ldap_unbind_s(connection);
          return(-3);
        }
        strcpy(ldap_returns[count], *bv_val);
      }
    }
    ldap_value_free(bv_val);
  }

  /* Add in some extra for the separators and terminating NULL */
  *len_return += attrcount;

  if ((*str_return = (char *)malloc(*len_return)) == NULL){
    PERDITION_LOG(LOG_DEBUG, "db_server_get: servername malloc");
    ldap_value_free(bv_val);
    return(-3);
  }

  /* Build the return string */
  strcpy(*str_return, ldap_returns[0]);
  free(ldap_returns[0]);
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
    }
  }
  free(ldap_returns);
  
  ldap_unbind_s(connection);

  return(0);
}
