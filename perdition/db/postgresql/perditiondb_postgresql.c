/**********************************************************************
 * perditiondb_postgresql.h                                  April 2000
 * Horms                                            horms@vergenet.net.
 *
 * Access a PostgreSQL database
 *
 * Adapted from code contributed for access to MySQL by:
 * Frederic Delchambre                                     October 1999
 * N.T.S. / Freegates                                dedel@freegates.be
 *                                             http://www.freegates.be/
 *                                                   http://www.nts.be/
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999  Horms and Frederic Delchambre
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

#include "perditiondb_postgresql.h"

static vanessa_dynamic_array_t *a=NULL;
static char *dbhost  = PERDITIONDB_PGSQL_DEFAULT_DBHOST;
static char *dbport  = PERDITIONDB_PGSQL_DEFAULT_DBPORT;
static char *dbname  = PERDITIONDB_PGSQL_DEFAULT_DBNAME;
static char *dbtable = PERDITIONDB_PGSQL_DEFAULT_DBTABLE;
static char *dbuser  = PERDITIONDB_PGSQL_DEFAULT_DBUSER;
static char *dbpwd   = PERDITIONDB_PGSQL_DEFAULT_DBPWD;


/**********************************************************************
 * perditiondb_postgresql_log
 * Show an error message with postgresql errors
 * pre: msg_str: message to prepent to message
 *      conn: postgresql database connection that error is for
 * post: msg_str is loged to PERDITION_LOG with postgresql error appended
 * return: none
 **********************************************************************/

static void perditiondb_postgresql_log(char *msg_str, PGconn *conn){
   PERDITION_LOG(LOG_DEBUG, "%s: %s",msg_str,PQerrorMessage(conn));
}


/**********************************************************************
 * dbserver_fini
 * Free static vanessa_dynamic_array_t a if it has been initialised
 * pre: none
 * post: static vanessa_dynamic_array_t a and its contents are freed
 * return:  0 on sucess
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_fini(void){
   if(a!=NULL){
     vanessa_dynamic_array_destroy(a);
     a=NULL;
   }
   return(0);
}


/**********************************************************************
 * dbserver_init
 * Parse options string.
 * pre: options_str: Options string. Sting is of the form
 * [dbhost[:dbport[:dbname[:dbtable[:dbuser[:dbpwd]]]]]]
 * post: Options string is parsed if not null into 
 *       static vanessa_dynamic_array_t a and 
 *       static char *dbhost, *dbname, *dbtable, *dbuser, *dbpwd are
 *       set to pointers insiside a or defaults as neccesary.
 * return:  0 on sucess
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_init(char *options_str){
   int count;

   if(options_str!=NULL && a==NULL){
     if((a=vanessa_dynamic_array_split_str(
       options_str, 
       PERDITIONDB_PGSQL_FIELD_DELIMITER
     ))==NULL){
       PERDITION_LOG(
	 LOG_DEBUG, 
	 "dbserver_init: vanessa_dynamic_array_split_str"
       );
       a=NULL;
       return(-1);
     }
     count=vanessa_dynamic_array_get_count(a);
     if(count>PERDITIONDB_PGSQL_DBHOST){ 
       dbhost=vanessa_dynamic_array_get_element(a, PERDITIONDB_PGSQL_DBHOST); 
     }
     if(count>PERDITIONDB_PGSQL_DBPORT){ 
       dbport=vanessa_dynamic_array_get_element(a, PERDITIONDB_PGSQL_DBPORT); 
     }
     if(count>PERDITIONDB_PGSQL_DBNAME){ 
       dbname=vanessa_dynamic_array_get_element(a, PERDITIONDB_PGSQL_DBNAME); 
     }
     if(count>PERDITIONDB_PGSQL_DBTABLE){ 
       dbtable=vanessa_dynamic_array_get_element(a, PERDITIONDB_PGSQL_DBTABLE);
     }
     if(count>PERDITIONDB_PGSQL_DBUSER){ 
       dbuser=vanessa_dynamic_array_get_element(a, PERDITIONDB_PGSQL_DBUSER); 
     }
     if(count>PERDITIONDB_PGSQL_DBPWD){ 
       dbpwd=vanessa_dynamic_array_get_element(a, PERDITIONDB_PGSQL_DBPWD); 
     }
   }

   return(0);
}


/**********************************************************************
 * truncate_str
 * truncate a string at the first instance of a character c by
 * replacing c with '\0'
 * pre: str: string to truncate
 *      c:   character to truncate at
 * post: Sting is truncated at first instance of c
 *       No change if c can't be found in the string
 * return: 1 if truncation is done
 *         0 otherwise
 **********************************************************************/

static int truncate_str(char *str, const char c){
  char *end;

  if((end=strchr(str, c))==NULL){
    return(0);
  }	

  *end='\0';
  return(1);
}


/**********************************************************************
 * dbserver_get
 * Read the server information for a given key from the MySQL db
 * specified in the options string. If fields are missing
 * from the options string, or it is NULL then defaults are
 * used as necessary.
 * pre: key_str:     Key as a null terminated string
 *      options_str: Options string. The usage of this is 
 *                   implementation dependant.
 *      str_return:  Value is returned here
 *      len_return:  Length of value is returned here
 * post: The str_key is looked up and the corresponding value is 
 *       returned in str_return and len_return.
 * return:  0 on sucess
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 * Note: The string returned in str_return should be of the 
 * form <servername>[:<port>].
 * E.g.: localhost:110
 *       localhost
 **********************************************************************/

int dbserver_get(
  char   *key_str,
  char   *options_str,
  char   **str_return,
  size_t *len_return
){
   PGresult *res;
   PGconn *conn;
   char *port = NULL;
   char *servername = NULL;
   char sqlstr[256];
   size_t servername_len;

   conn = PQsetdbLogin(dbhost, dbport, NULL, NULL, dbname, dbuser, dbpwd);
   if(PQstatus(conn) == CONNECTION_BAD){  
     perditiondb_postgresql_log("dbserver_init: PQsetdbLogin", conn);
     PQfinish(conn);
     return(-1);
   }

   if(snprintf(
     sqlstr, 
     256,
     "select * from %s where \"user\"='%s'",
     dbtable, 
     key_str
   )<0){
     PERDITION_LOG(LOG_DEBUG, "db_server_get: query truncated, aborting");
     PQfinish(conn);
     return(-3);
   }

   res = PQexec(conn, sqlstr);
   if(!res || PQresultStatus(res) != PGRES_TUPLES_OK){  
     perditiondb_postgresql_log("db_server_get: PQexec", conn);
     PQclear(res);
     PQfinish(conn);
     return(-1);
   }


   /* 
    * If no tuples were found  or the servername is null then leave, 
    * else continue using the first tuple.
    */
   if(PQntuples(res)<1 || PQgetisnull(res, 0, 1)){
     PQclear(res);
     PQfinish(conn);
     return(-1);
   }
   
   servername=PQgetvalue(res, 0, 1);
   /*
    * Grr, postgres seems to return a ' ' padded string
    */
   truncate_str(servername, ' ');
   if(*servername=='\0'){
     PQclear(res);
     PQfinish(conn);
     return(-1);
   }
   servername_len=*len_return=1+strlen(servername);

   if(!PQgetisnull(res, 0, 2)){
     port=PQgetvalue(res, 0, 2);
     /*
      * Grr, postgres seems to return a ' ' padded string
      */
     truncate_str(port, ' ');
     if(*port=='\0'){
     	port=NULL;
     }
     else {
       *len_return+=1+strlen(port);
     }
   }


   if((*str_return=(char *)malloc(*len_return))==NULL){  
     PERDITION_LOG(LOG_DEBUG,"db_server_get: str_return malloc");
     PQclear(res);
     PQfinish(conn);
     return(-3);
   }

   strcpy(*str_return, servername);
   if(port!=NULL){
     *((*str_return)+servername_len-1)=PERDITIONDB_PGSQL_FIELD_DELIMITER;
     strcpy((*str_return)+servername_len,port);
   }

   PQclear(res);
   PQfinish(conn);
   return(0);
}
