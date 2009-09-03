/**********************************************************************
 * perditionb_odbc.c                                         March 2002
 * Horms                                             horms@verge.net.au
 *
 * Access a database using ODBC
 *
 * Adapted from code contributed by:
 * Frederic Delchambre                                     October 1999
 * N.T.S. / Freegates                                dedel@freegates.be
 *                                             http://www.freegates.be/
 *                                                   http://www.nts.be/
 *
 * With help from the ODBC Programming Tutorial
 * http://www.unixodbc.org/
 *
 * perdition
 * Mail retrieval proxy server, MySQL support
 * Copyright (C) 1999-2005  Horms and Frederic Delchambre
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

#include "perditiondb_odbc.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


static vanessa_dynamic_array_t *a = NULL;
static char *dbhost = PERDITIONDB_ODBC_DEFAULT_DBHOST;
static char *dbname = PERDITIONDB_ODBC_DEFAULT_DBNAME;
static unsigned int dbport = PERDITIONDB_ODBC_DEFAULT_DBPORT;
static char *dbtable = PERDITIONDB_ODBC_DEFAULT_DBTABLE;
static char *dbuser = PERDITIONDB_ODBC_DEFAULT_DBUSER;
static char *dbpwd = PERDITIONDB_ODBC_DEFAULT_DBPWD;
static char *db_user_col = PERDITIONDB_ODBC_DEFAULT_DBUSERCOL;
static char *db_srv_col = PERDITIONDB_ODBC_DEFAULT_DBSRVCOL;
static char *db_port_col = PERDITIONDB_ODBC_DEFAULT_DBPORTCOL;


/**********************************************************************
 * perditiondb_odbc_log
 * Show an error message with odbc errors
 * pre: msg_str: message to prepent to message
 *      db: odbc database that error is for
 * post: msg_str is logged to VANESSA_LOGGER_DEBUG with odbc error appended
 * return: none
 **********************************************************************/

void perditiondb_odbc_log(const char *msg_str, SQLHDBC hdbc)
{
	char stat[10];
	char msg[202];
	SQLINTEGER err;
	SQLSMALLINT len;

	SQLGetDiagRec(SQL_HANDLE_DBC, hdbc, 1, stat, &err, msg, 100, &len);
	VANESSA_LOGGER_LOG_UNSAFE(LOG_DEBUG, "%s: %s (%d)", msg_str, msg, err);
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
	if (a != NULL) {
		vanessa_dynamic_array_destroy(a);
		a = NULL;
	}
	return (0);
}


/**********************************************************************
 * dbserver_init
 * Parse options string.
 * pre: options_str: Options string. String is of the form
 * [dbhost[:port[:DSN[:dbtable[:dbuser[:dbpwd[:dbsrvcol[:dbusercol[:dbportcol]]]]]]]]]
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

int dbserver_init(char *options_str)
{
	int count;
	char *tmp_str;

	if (options_str == NULL || a != NULL) {
		return (0);
	}

	tmp_str = strdup(options_str);
	if (tmp_str == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("strdup");
		return (-1);
	}

	a = vanessa_dynamic_array_split_str(tmp_str,
				 PERDITIONDB_ODBC_FIELD_DELIMITER);
	if (a == NULL) {
		VANESSA_LOGGER_DEBUG("vanessa_dynamic_array_split_str");
		a = NULL;
		free(tmp_str);
		return (-1);
	}

	count = vanessa_dynamic_array_get_count(a);
	if (count > PERDITIONDB_ODBC_DBHOST) {
		dbhost = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBHOST);
	}
	if (count > PERDITIONDB_ODBC_DBNAME) {
		dbname = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBNAME);
	}
	if (count > PERDITIONDB_ODBC_DBPORT) {
		dbport = atoi(vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBPORT));
	}
	if (count > PERDITIONDB_ODBC_DBTABLE) {
		dbtable = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBTABLE);
	}
	if (count > PERDITIONDB_ODBC_DBUSER) {
		dbuser = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBUSER);
	}
	if (count > PERDITIONDB_ODBC_DBPWD) {
		dbpwd = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBPWD);
	}
	if (count > PERDITIONDB_ODBC_DBUSERCOL) {
		db_user_col = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBUSERCOL);
	}
	if (count > PERDITIONDB_ODBC_DBSRVCOL) {
		db_srv_col = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBSRVCOL);
	}
	if (count > PERDITIONDB_ODBC_DBPORTCOL) {
		db_port_col = vanessa_dynamic_array_get_element(a,
				PERDITIONDB_ODBC_DBPORTCOL);
	}

	free(tmp_str);

	return (0);
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

int dbserver_get(const char *key_str, const char *options_str, 
		char **str_return, size_t * len_return)
{
	SQLINTEGER rc;
	SQLINTEGER rc2;
	int status = -1;
	SQLHENV env;
	SQLHDBC hdbc;
	SQLHSTMT hstmt;

	size_t servername_len;
	char sqlstr[PERDITIONDB_ODBC_QUERY_LENGTH];
	char user_res[PERDITIONDB_ODBC_RESULT_LENGTH];
	char server_res[PERDITIONDB_ODBC_RESULT_LENGTH];
	char port_res[PERDITIONDB_ODBC_RESULT_LENGTH];

	/* Allocate environment handle */
	rc = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		VANESSA_LOGGER_DEBUG("SQLAllocHandle: environment handle");
		return (-1);
	}

	/* Register version */
	rc = SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION,
			   (void *) SQL_OV_ODBC3, 0);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		VANESSA_LOGGER_DEBUG("SQLSetEnvATTR");
		goto err_env;
	}

	/* Allocate connection handle */
	rc = SQLAllocHandle(SQL_HANDLE_DBC, env, &hdbc);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		VANESSA_LOGGER_DEBUG("SQLAllocHandle: connection handle");
		goto err_env;
	}

	/* Set timeout */
	SQLSetConnectAttr(hdbc, SQL_LOGIN_TIMEOUT, (SQLPOINTER *) 5, 0);

	/* Connect */
	rc = SQLConnect(hdbc, (SQLCHAR *) dbname, SQL_NTS,
			(SQLCHAR *) dbuser, SQL_NTS,
			(SQLCHAR *) dbpwd, SQL_NTS);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		perditiondb_odbc_log("SQLConnect", hdbc);
		goto err_hdbc;
	}

	/* Allocate statement handle */
	rc = SQLAllocHandle(SQL_HANDLE_STMT, hdbc, &hstmt);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		perditiondb_odbc_log("SQLAllocHandle", hdbc);
		goto err_connect;
	}

	/* Form Query */
	memset(sqlstr, 0, PERDITIONDB_ODBC_QUERY_LENGTH);
	if (db_port_col && db_port_col[0]) {
		rc = snprintf(sqlstr, PERDITIONDB_ODBC_QUERY_LENGTH-1, 
				"select %s, %s, %s from %s "
				"where %s = '%s';",
				db_user_col, db_srv_col, db_port_col, dbtable, 
				db_user_col, key_str);
	}
	else {
		rc = snprintf(sqlstr, PERDITIONDB_ODBC_QUERY_LENGTH-1, 
				" select %s, %s from %s where %s = '%s'; ",
				db_user_col, db_srv_col, dbtable, db_user_col,
				key_str);
	}
	if (rc < 0) {
		VANESSA_LOGGER_DEBUG(" query truncated, aborting ");
		goto err_hdbc;
	}

	/* Bind Columns */
	rc = SQLBindCol(hstmt, 1, SQL_C_CHAR, &user_res, 
			PERDITIONDB_ODBC_QUERY_LENGTH, &rc2);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		perditiondb_odbc_log("SQLBindCol: 1", hdbc);
		goto err_hstmt;
	}
	SQLBindCol(hstmt, 2, SQL_C_CHAR, &server_res, 
			PERDITIONDB_ODBC_QUERY_LENGTH, &rc2);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		perditiondb_odbc_log("SQLBindCol: 2", hdbc);
		goto err_hstmt;
	}
	SQLBindCol(hstmt, 3, SQL_C_CHAR, &port_res, 
			PERDITIONDB_ODBC_QUERY_LENGTH, &rc2);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		perditiondb_odbc_log("SQLBindCol: 3", hdbc);
		goto err_hstmt;
	}

	/* Make Query */
	rc = SQLExecDirect(hstmt, sqlstr, SQL_NTS);
	if ((rc != SQL_SUCCESS) && (rc != SQL_SUCCESS_WITH_INFO)) {
		VANESSA_LOGGER_DEBUG("SQLExecDirect");
		goto err_hstmt;
	}

	/* Fetch the first result only */
	rc = SQLFetch(hstmt);
	if(rc == SQL_NO_DATA) {
		status = -2;
		goto err_hstmt;
	}

	status = -3;
   	if(*server_res=='\0'){  
		VANESSA_LOGGER_DEBUG("server_res is empty ");
		goto err_hstmt;
	}
   	servername_len=*len_return=1+strlen(server_res);

   	if (db_port_col!=NULL && *db_port_col!='\0' && *port_res!='\0'){
       		*len_return+=1+strlen(port_res);
   	}

   	if((*str_return=(char *)malloc(*len_return))==NULL){  
     		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		goto err_hstmt;
	}

   	strcpy(*str_return, server_res);
   	if (db_port_col!=NULL && *db_port_col!='\0' && *port_res!='\0'){
		*((*str_return)+servername_len-1) =
			PERDITIONDB_ODBC_FIELD_DELIMITER;
       		strcpy((*str_return)+servername_len, port_res);
	}

	/* Lets get out of here mate */
   	status=0;
err_hstmt:
	SQLFreeHandle(SQL_HANDLE_DBC, hstmt);
err_connect:
	SQLDisconnect(hdbc);
err_hdbc:
	SQLFreeHandle(SQL_HANDLE_DBC, hdbc);
err_env:
	SQLFreeHandle(SQL_HANDLE_DBC, env);
	return(status);
}


