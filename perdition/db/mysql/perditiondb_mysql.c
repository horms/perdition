/**********************************************************************
 * perditionb_mysql.c                                     December 1999
 * Horms                                             horms@verge.net.au
 *
 * Access a MySQL database
 *
 * Adapted from code contributed by:
 * Frederic Delchambre                                     October 1999
 * N.T.S. / Freegates                                dedel@freegates.be
 *                                             http://www.freegates.be/
 *                                                   http://www.nts.be/
 * perdition
 * Mail retrieval proxy server, MySQL support
 * Copyright (C) 1999-2003  Horms and Frederic Delchambre
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

#include "perditiondb_mysql.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


static vanessa_dynamic_array_t *a=NULL;
static char *dbhost          = PERDITIONDB_MYSQL_DEFAULT_DBHOST;
static char *dbname          = PERDITIONDB_MYSQL_DEFAULT_DBNAME;
static unsigned int dbport   = PERDITIONDB_MYSQL_DEFAULT_DBPORT;
static char *dbtable         = PERDITIONDB_MYSQL_DEFAULT_DBTABLE;
static char *dbuser          = PERDITIONDB_MYSQL_DEFAULT_DBUSER;
static char *dbpwd           = PERDITIONDB_MYSQL_DEFAULT_DBPWD;
static char *db_user_col     = PERDITIONDB_MYSQL_DEFAULT_DBUSERCOL;
static char *db_srv_col      = PERDITIONDB_MYSQL_DEFAULT_DBSRVCOL;
static char *db_port_col     = PERDITIONDB_MYSQL_DEFAULT_DBPORTCOL;


/**********************************************************************
 * perditiondb_mysql_log
 * Show an error message with mysql errors
 * pre: msg_str: message to prepent to message
 *      db: mysql database that error is for
 * post: msg_str is logged to VANESSA_LOGGER_DEBUG with mysql error appended
 * return: none
 **********************************************************************/

#define perditiondb_mysql_log(msg_str, db) \
   VANESSA_LOGGER_DEBUG_UNSAFE("%s: %s", msg_str, mysql_error(db))


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
 * pre: options_str: Options string. String is of the form
 * [dbhost[:port[:dbname[:dbtable[:dbuser[:dbpwd[:dbusercol[:dbsrvcol[:dbportcol]]]]]]]]]
 * post: Options string is parsed if not null into 
 *       static vanessa_dynamic_array_t a and 
 *       static char *dbhost, *dbname, *dbtable, *dbuser, *dbpwd are
 *       set to pointers insiside a or defaults as neccesary.
 * return:  0 on success
 *         -1 on db access error
 *            This inclides file, connection and other data access
 *            errors. It does not cover memory allocation problems.
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_init(char *options_str){
   int count;
   char *tmp_str;

   if(options_str==NULL || a!=NULL){
     return(0);
   }

   if((tmp_str=strdup(options_str))==NULL) {
     VANESSA_LOGGER_DEBUG_ERRNO("strdup");
     a=NULL;
     return(-1);
   }

   if((a=vanessa_dynamic_array_split_str(
     tmp_str, 
     PERDITIONDB_MYSQL_FIELD_DELIMITER
   ))==NULL){
     VANESSA_LOGGER_DEBUG("vanessa_dynamic_array_split_str");
     a=NULL;
     free(tmp_str);
     return(-1);
   }

   count=vanessa_dynamic_array_get_count(a);
   if(count>PERDITIONDB_MYSQL_DBHOST){ 
     dbhost=vanessa_dynamic_array_get_element(a, PERDITIONDB_MYSQL_DBHOST); 
   }
   if(count>PERDITIONDB_MYSQL_DBNAME){ 
     dbname=vanessa_dynamic_array_get_element(a, PERDITIONDB_MYSQL_DBNAME); 
   }
   if(count>PERDITIONDB_MYSQL_DBPORT){ 
     dbport=atoi(vanessa_dynamic_array_get_element(a, 
	   PERDITIONDB_MYSQL_DBPORT)); 
   }
   if(count>PERDITIONDB_MYSQL_DBTABLE){ 
     dbtable=vanessa_dynamic_array_get_element(a, PERDITIONDB_MYSQL_DBTABLE);
   }
   if(count>PERDITIONDB_MYSQL_DBUSER){ 
     dbuser=vanessa_dynamic_array_get_element(a, PERDITIONDB_MYSQL_DBUSER); 
   }
   if(count>PERDITIONDB_MYSQL_DBPWD){ 
     dbpwd=vanessa_dynamic_array_get_element(a, PERDITIONDB_MYSQL_DBPWD); 
   }
   if(count>PERDITIONDB_MYSQL_DBUSERCOL){ 
     db_user_col=vanessa_dynamic_array_get_element(
	 a, 
	 PERDITIONDB_MYSQL_DBUSERCOL
     ); 
   }
   if(count>PERDITIONDB_MYSQL_DBSRVCOL){ 
     db_srv_col=vanessa_dynamic_array_get_element(
	 a, 
	 PERDITIONDB_MYSQL_DBSRVCOL
     ); 
   }
   if(count>PERDITIONDB_MYSQL_DBPORTCOL){ 
     db_port_col=vanessa_dynamic_array_get_element(
	 a, 
	 PERDITIONDB_MYSQL_DBPORTCOL
     ); 
   }

   free(tmp_str);

   return(0);
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
 **********************************************************************/

int dbserver_get(
  const char   *key_str,
  const char   *options_str,
  char   **str_return,
  size_t *len_return
){
   MYSQL db;
   long rc;
   MYSQL_RES *res;
   MYSQL_ROW row;
   char sqlstr[PERDITIONDB_MYSQL_QUERY_LENGTH];
   size_t servername_len;

   (MYSQL*)rc = mysql_init(&db);
   if(!rc){  
     perditiondb_mysql_log("mysql_init", &db);
     vanessa_dynamic_array_destroy(a);
     return(-1);
   }

   (MYSQL*)rc=mysql_real_connect(&db,dbhost,dbuser,dbpwd,dbname,dbport,NULL,0);
   if(!rc){  
     perditiondb_mysql_log("mysql_connect", &db);
     mysql_close(&db);
     return(-1);
   }

   if (db_port_col && db_port_col[0]) {
     if(snprintf(
       sqlstr, 
       PERDITIONDB_MYSQL_QUERY_LENGTH, 
       "select %s,%s,%s from %s where %s='%s';",
       db_user_col, 
       db_srv_col, 
       db_port_col,
       dbtable, 
       db_user_col,
       key_str
     )<0){
       VANESSA_LOGGER_DEBUG("query truncated, aborting");
       return(-3);
     }
   }
   else {
     if(snprintf(
       sqlstr, 
       PERDITIONDB_MYSQL_QUERY_LENGTH, 
       "select %s,%s from %s where %s='%s';",
       db_user_col, db_srv_col,
       dbtable, db_user_col,
       key_str
     )<0){
       VANESSA_LOGGER_DEBUG("query truncated, aborting");
       return(-3);
     }
   }

   rc = mysql_query(&db, sqlstr);
   if(rc){  
     perditiondb_mysql_log("mysql_query", &db);
     mysql_close(&db);
     return(-1);
   }

   res = mysql_store_result(&db);
   if(!res){  
     perditiondb_mysql_log("mysql_store_result", &db);
     mysql_close(&db);
     return(-3);
   }

   if(mysql_num_rows(res) == 0){
     mysql_free_result(res);
     mysql_close(&db);
     return(-2);
   }

   if((row=mysql_fetch_row(res))==NULL){
     perditiondb_mysql_log("mysql_fetch_row", &db);
     mysql_close(&db);
     return(-3);
   }

   if(row[1]==NULL || row[1][0]=='\0'){  
     VANESSA_LOGGER_DEBUG("row[1] is empty");
     mysql_free_result(res);
     mysql_close(&db);
     return(-3);
   }
   servername_len=*len_return=1+strlen(row[1]);

   if (db_port_col && db_port_col[0]){
     if(row[2]!=NULL && row[2][0]!='\0'){
       *len_return+=1+strlen(row[2]);
     }
   }

   if((*str_return=(char *)malloc(*len_return))==NULL){  
     VANESSA_LOGGER_DEBUG_ERRNO("malloc");
     mysql_free_result(res);
     mysql_close(&db);
     return(-3);
   }

   strcpy(*str_return,row[1]);
   if (db_port_col && db_port_col[0]){
     if(row[2]!=NULL && row[2][0]!='\0'){
       *((*str_return)+servername_len-1)=PERDITIONDB_MYSQL_FIELD_DELIMITER;
       strcpy((*str_return)+servername_len,row[2]);
     }
   }
   
   mysql_free_result(res);
   mysql_close(&db);
   return(0);
}
