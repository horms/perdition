/**********************************************************************
 * getserver.c                                            December 1999
 * Horms                                             horms@vergenet.net
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
 * Copyright (C) 1999-2001  Horms
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


#include "getserver.h"


/**********************************************************************
 * getserver
 * Read the server information for a given key using * the function 
 * dbserver_get. 
 * pre: key_str: key to lookup
 *      dbserver_get: function to do the lookup
 * return: server_port_t stucture containing server and port.
 *         NULL on error
 **********************************************************************/

server_port_t *getserver(
  char *key_str, 
  int (*dbserver_get)(char *, char *, char **, size_t *)
){
  server_port_t *server_port=NULL;
  char *content_str;
  int  content_len;
  char *popserver;
  int  key_len;
  int status;
 
  extern options_t opt;

  if(
    opt.client_server_specification &&
    (popserver=strstr(key_str, opt.domain_delimiter)) != NULL 
  ){
    *popserver='\0';
    if((server_port=server_port_create())==NULL){
      PERDITION_DEBUG("server_port_create");
      return(NULL);
    }
    server_port_strn_assign(
      server_port,
      popserver+opt.domain_delimiter_length,
      strlen(popserver+opt.domain_delimiter_length)
    );
  }
  else{
    key_len=strlen(key_str);
    status=dbserver_get(key_str,opt.map_library_opt,&content_str,&content_len);
    if(status<0){
      if(status!=-2){
        PERDITION_DEBUG("dbserver_get");
      }
      return(NULL);
    }
    if((server_port=server_port_create())==NULL){
      PERDITION_DEBUG("server_port_create");
      return(NULL);
    }
    server_port=server_port_strn_assign(server_port, content_str, content_len);
    free(content_str);
  }
  return(server_port);
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
  int (**dbserver_get_return)(char *, char *, char **, size_t *)
){
  char *error;
  int *(*dbserver_init)(char *);
  extern options_t opt;

  *handle_return=dlopen(libname, RTLD_LAZY);
  if(!*handle_return) {
    error=dlerror();
    if(opt.debug){
      fprintf(stderr, "dlopen failed: %s\n", error);
    }
    PERDITION_DEBUG("dlopen: %s", error);
    return(-1);
  }

  *dbserver_get_return=dlsym(*handle_return, "dbserver_get");
  if((error=dlerror())!=NULL){
    if(opt.debug){
      fprintf(stderr, "Could not find symbol dbserver_get: %s", error);
    }
    PERDITION_DEBUG("dlsym: %s", error);
    dlclose(*handle_return);
    return(-1);
  }
  dbserver_init=dlsym(*handle_return, "dbserver_init");
  if((error=dlerror())==NULL){
    if(dbserver_init(options_str)){
      if(opt.debug){
        fprintf(stderr, "Error running dbserver_init: %s\n", error);
      }
      PERDITION_DEBUG("dbserver_init: %s", error);
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

  dbserver_fini=dlsym(handle, "dbserver_fini");
  if((error=dlerror())==NULL){
    if(dbserver_fini()){
      PERDITION_DEBUG("dbserver_fini: %s", error);
      status=-1;
    }
  }
  dlclose(handle);

  return(status);
}
