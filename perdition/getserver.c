/**********************************************************************
 * getserver.c                                            December 1999
 * Horms                                             horms@verge.net.au
 *
 * Access a database
 *
 * The database is accessed using the dlopen mechanism on a library.
 * The library should define the symbol
 * int (*dbserver_get)(char *, char *, char **, size_t *)
 * with the following semantics.
 *
 ************************************************************
 * dbserver_get
 * Find the server (value) given the user (key)
 * pre: key_str:     Key as a null terminated string
 *      options_str: Options string. The usage of this is 
 *                   implementation dependant.
 *      str_return:  Value is returned here
 *      len_return:  Length of value is returned here
 * post: The str_key is looked up and the corresponding value is 
 *       returned in str_return and len_return.
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 * Note: The string returned in str_return should be of the 
 * form <servername>[:<port>].
 * E.g.: localhost:110
 *       localhost
 ************************************************************
 *
 * As the library is opened using the dlopen mechanism the libary
 * may also export functions _init and _fini that will be
 * executed when the library is opened and closed respectively.
 * In addition if the symbols int *(*dbserver_init)(char *) and 
 * int *(*dbserver_fini)(void) are defined then these are run when 
 * the library is opened and closed respectivley.  If defined these 
 * symbols should have the following semantics.
 *
 ************************************************************
 * dbserver_init
 * Initialise db as necessary
 * pre: options_str: Options string. The usage of this is 
 *                   implementation dependant.
 * post: db is intialised
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 ************************************************************
 * dbserver_fini
 * Shut down db as necessary
 * pre: none
 * post: db is shut down
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 ************************************************************
 *
 * In additoin, if a SIGHUP is sent to a process then a signal handler
 * will call dbserver_fini if it is defined and then
 * dbserver_init if it is defined. Note: dbserver_init will be 
 * called if defined, even if dbserver_fini id not defoned.
 *
 * Client server specification code courtesy of Daniel Roesen,
 * <droesen@entire-systems.com>. 
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2003  Horms
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
 *
 **********************************************************************/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "getserver.h"


#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define _GKS_CHUNK_SIZE 32

#define _GSK_STR_ADD(_str, _size) \
	if(key_str_space < (_size)) { \
		key_str_size += (_size) + _GKS_CHUNK_SIZE; \
		key_str_space += (_size) + _GKS_CHUNK_SIZE; \
		key_str = (char *)realloc(key_str, key_str_size); \
		if(key_str == NULL) { \
			VANESSA_LOGGER_DEBUG_ERRNO("realloc"); \
			return(NULL); \
		} \
		key_str_p = key_str + key_str_size - key_str_space; \
	} \
	strncpy(key_str_p, (_str), (_size)); \
	key_str_space -= (_size); \
	key_str_p += (_size);

#define _GSK_STR_ADD_C(_c) \
{ \
	char c; \
	c = (_c); \
	_GSK_STR_ADD(&c, 1); \
}

#define _GSK_STR_ADD_STR(_str) \
	_GSK_STR_ADD(_str, strlen(_str));

#define _GSK_SPLIT_USER(_full_user_str) \
	if(domain_str == NULL) { \
		domain_str = strrstr((_full_user_str), opt.domain_delimiter); \
		user_str = (_full_user_str); \
		if(domain_str == NULL) { \
			user_str_size = strlen(_full_user_str); \
		} \
		else { \
			user_str_size = domain_str-user_str; \
			domain_str++; \
		} \
	}


static char *getserver_key_str(const char *query_fmt, 
		const char *full_user_str, const char *from_str, 
		const char *to_str, const uint16 from_port,
		const uint16 to_port)
{
        const char *user_str=NULL;
        char *domain_str=NULL;
	size_t user_str_size=0;
	char to_port_str[6];
	char from_port_str[6];
        const char *c;

	char *key_str=NULL;
	char *key_str_p=NULL;
	size_t key_str_space=0;
	size_t key_str_size=0;

        int have_escape = 0;

	extern options_t opt;

        /* \U: Username
         * \u: Username (bit before domain delimiter)
         * \D: domain delimiter
         * \d: Domain (but after domain delimiter)
         * \i: Source IP address
         * \I: Destination IP address
         * \p: Source port
         * \P: Destination port
	 * \\: Literal \
         */

        for(c = query_fmt; *c != '\0'; c++) {
		/* Handle escape */
		if(*c == '\\' && !have_escape) {
			have_escape = 1;
			continue;
		}

		/* Deal with Literals */
		if(!have_escape) {
			_GSK_STR_ADD(c, 1);
			continue;
		}

		/* Handle escape codes */
		switch(*c) {
			case 'U':
				_GSK_STR_ADD_STR(full_user_str);
				break;
			case 'u':
				_GSK_SPLIT_USER(full_user_str);
				_GSK_STR_ADD(user_str, user_str_size);
				break;
			case 'D':
				_GSK_STR_ADD_STR(opt.domain_delimiter);
				break;
			case 'd':
				_GSK_SPLIT_USER(full_user_str);
				if(domain_str) {
					_GSK_STR_ADD_STR(domain_str);
				}
				break;
			case 'i':
				_GSK_STR_ADD_STR(from_str);
				break;
			case 'I':
				_GSK_STR_ADD_STR(to_str);
				break;
			case 'p':
				snprintf(to_port_str, 6, "%hu", from_port);
				from_port_str[5] = '\0';
				_GSK_STR_ADD_STR(from_port_str);
				break;
			case 'P':
				snprintf(to_port_str, 6, "%hu", to_port);
				to_port_str[5] = '\0';
				_GSK_STR_ADD_STR(to_port_str);
				break;
			case '\\':
				_GSK_STR_ADD_C('\\');
				break;
			default:
				VANESSA_LOGGER_DEBUG_UNSAFE("Unknown escape "
						"sequence: \\%c", *c);
				return(NULL);
		}
		have_escape=0;

        }       

	_GSK_STR_ADD_C('\0');
	VANESSA_LOGGER_DEBUG_UNSAFE("\"%s\"->\"%s\"", query_fmt, key_str);
	return(key_str);
}       


/**********************************************************************
 * getserver
 * Read the server information for a given key using * the function 
 * dbserver_get. 
 * pre: key_str: key to lookup
 *      dbserver_get: function to do the lookup
 * return: server_port_t stucture containing server and port.
 *         NULL on error
 **********************************************************************/

static int 
do_getserver(
  const char *key_str, 
  int (*dbserver_get)(const char *, const char *, char **, size_t *),
  int (*dbserver_get2)(const char *, const char *, char **, char **, char **),
  user_server_port_t **usp_ret 

){
	char *user_str = NULL;
	char *server_str = NULL;
	size_t  server_len = 0;
	char *port_str = NULL;
	int status = 0;

	extern options_t opt;

	*usp_ret = NULL;

	if(dbserver_get) {
		status = dbserver_get(key_str, opt.map_library_opt,
				&server_str, &server_len);
	}
	else if (dbserver_get2){
		status = dbserver_get2(key_str, opt.map_library_opt,
				&user_str, &server_str, &port_str);
	}
	else {
		VANESSA_LOGGER_DEBUG("Neither dbserver_get nor "
				"dbserver_get2 supplied");
		goto fail;
	}

	if(status < 0) {
		goto fail;
	}

	/* Check for an empty result */
	if(!server_str || *server_str=='\0') {
		VANESSA_LOGGER_DEBUG("dbserver_get returned empty string");
		goto fail;
	}

	if(dbserver_get) {
		if(user_server_port_strn_assign(usp_ret, server_str) < 0) {
			VANESSA_LOGGER_DEBUG("user_server_port_strn_assign");
			goto fail;
		}
	}
	else {
		if(user_server_port_assign(usp_ret, user_str, server_str, 
				port_str) < 0) {
			VANESSA_LOGGER_DEBUG("user_server_port_str_assign");
			goto fail;
		}
	}

	return(status);

fail:
	str_free(user_str);
	str_free(server_str);
	str_free(port_str);
	if(*usp_ret) {
		free(*usp_ret);
		*usp_ret = NULL;
	}
	return(status);
}
			

user_server_port_t 
	*getserver(
  const char *user_str, const char *from_str, const char *to_str, 
  const uint16 from_port, const uint16 to_port, 
  int (*dbserver_get)(const char *, const char *, char **, size_t *),
  int (*dbserver_get2)(const char *, const char *, char **, char **, char **))
{
  user_server_port_t *usp=NULL;
  char *popserver;
  int status = -1;
 
  extern options_t opt;

  if(!dbserver_get && !dbserver_get2 && !opt.client_server_specification) {
    return(NULL);
  }

  /* If the user specified a server, and it is allowed then use it */
  if(
    opt.client_server_specification &&
    (popserver=strrstr(user_str, opt.domain_delimiter)) != NULL 
  ){
    *popserver='\0';
    if(user_server_port_strn_assign(&usp, 
        popserver+opt.domain_delimiter_length) < 0) {
      VANESSA_LOGGER_DEBUG("server_port_strn_assign");
      user_server_port_destroy(usp);
      return(NULL);
    }
    return(usp);
  }

  if(opt.query_key == NULL) {
  	status=do_getserver(user_str, dbserver_get, dbserver_get2, &usp);
  }
  else {
	  char *query_fmt;
	  char *key_str;
	  size_t count;
	  size_t i;

	  count = vanessa_dynamic_array_get_count(opt.query_key);

	  for(i = 0; i < count ; i++) {
		query_fmt=(char *)vanessa_dynamic_array_get_element(
				  opt.query_key, i);
		if(query_fmt == NULL) {
			status = -3;
			VANESSA_LOGGER_DEBUG(
					"vanessa_dynamic_array_get_element");
			return(NULL);
		}
		key_str = getserver_key_str(query_fmt, user_str, from_str,
				to_str, from_port, to_port);
		if(key_str == NULL) {
			VANESSA_LOGGER_DEBUG("getserver_key_str");
			return(NULL);
		}
  		status=do_getserver(key_str, dbserver_get, 
				dbserver_get2, &usp);
		free(key_str);
		if(status != -2) {
			break;
		}
	  }
  }

  /* Catch errors from any of the dbserver_get calls */
  if(status<0){
    if(status != -2) {
      VANESSA_LOGGER_DEBUG("do_dbserver_get");
    }
    return(NULL);
  }

  return(usp);
} 


/**********************************************************************
 * getserver_openlib
 * Open library for function to access user db (popmap)
 * pre: libname: library to open. Rules for the search path for
 *               this file are as per dlopen(3)
 *      handle_return: pointer to library handle will be placed here
 *      dbserver_get_return: pointer to dbserver_get will be placed here
 * post: Library is open and handle is put in *handle_return
 *       Symbol dbserver_get is accessed an put in *dbserver_get_return
 *       If the symbol dbserver_init is defined then it is run
 * return: 0 on success
 *         -1 on error
 **********************************************************************/

int getserver_openlib(
  char *libname,
  char *options_str,
  void **handle_return,
  int (**dbserver_get_return)(const char *, const char *, char **, size_t *),
  int (**dbserver_get2_return)(const char *, const char *, char **, 
	  char **, char **)
)
{
  char *error;
  int *(*dbserver_init)(char *);

  *dbserver_get_return = NULL;
  *dbserver_get2_return = NULL;

  if(libname == NULL || *libname == '\0') {
    *handle_return = NULL;
    *dbserver_get_return = NULL;
    return(0);
  }

  *handle_return=dlopen(libname, RTLD_LAZY);
  if(!*handle_return) {
    error=dlerror();
    VANESSA_LOGGER_DEBUG_UNSAFE("dlopen falied: %s", str_null_safe(error));
    return(-1);
  }

  *dbserver_get_return = dlsym(*handle_return, "dbserver_get");
  if((error=dlerror())!=NULL){
    *dbserver_get2_return = dlsym(*handle_return, "dbserver_get2");
    if((error=dlerror())!=NULL){
      VANESSA_LOGGER_DEBUG_UNSAFE("Could not find symbol "
		    "dbserver_get or dbserver_get2: dlsym: %s", error);
      dlclose(*handle_return);
      return(-1);
    }
  }

  dbserver_init=dlsym(*handle_return, "dbserver_init");
  if((error=dlerror())==NULL){
    if(dbserver_init(options_str)){
      VANESSA_LOGGER_DEBUG("dbserver_init");
      dlclose(*handle_return);
      return(-1);
    }
  }

  return(0);
}


/**********************************************************************
 * getserver_closelib
 * Close library for function to access user db (popmap)
 * pre: handle: library handle to close
 * post: If the symbol dbserver_fini is defined then it is run
 *       Library is closed
 * return: 0 on success
 *         -1 on error
 **********************************************************************/

int getserver_closelib(void *handle){
  int status=0;
  int *(*dbserver_fini)(void);
  char *error;

  if(handle == NULL) {
    return(0);
  }

  dbserver_fini=dlsym(handle, "dbserver_fini");
  if((error=dlerror())==NULL){
    if(dbserver_fini()){
      VANESSA_LOGGER_DEBUG("dbserver_fini");
      status=-1;
    }
  }
  dlclose(handle);

  return(status);
}
