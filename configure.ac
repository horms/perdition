######################################################################
# configure.in                                          September 2000
# Horms                                           <horms@verge.net.au>
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999-2005  Horms
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
#
######################################################################

AC_INIT(makegdbm/makegdbm.c)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(perdition, 1.18)

AC_PROG_CC
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CHECK_MEMBERS([struct sockaddr.sa_len], [], [], [[#include <sys/socket.h>]])

# Checks for libraries.
AC_CHECK_LIB(dl, dlopen,  [ dl_lib="-ldl" ], [ dl_lib="" ])
AC_CHECK_LIB(nsl, yp_match, true, true)
AC_CHECK_LIB(socket, socket, [ socket_lib="-lsocket" ], [ socket_lib="" ])
AC_CHECK_LIB(nsl, gethostbyname, [ nsl_lib="-lnsl" ], [ nsl_lib="" ])
AC_CHECK_LIB(crypt, crypt, [ crypt_lib="-lcrypt" ], [ crypt_lib="" ])
AC_CHECK_LIB(
  popt,
  poptGetContext,
  true,
AC_MSG_ERROR(
""
"**********************************************************************"
"* perdition requires the popt options parsing library available from"
"* ftp://ftp.rpm.org/pub/rpm/ and mirrors."
"**********************************************************************"
) ;\
)
AC_CHECK_LIB(
  vanessa_logger,
  vanessa_logger_closelog,
  true,
AC_MSG_ERROR(
""
"**********************************************************************"
"* perdition requires the vanessa_logger generic logging library"
"* available from"
"* http://www.vergenet.net/linux/vanessa/download/vanessa_logger/ and mirrors."
"**********************************************************************"
)
)
AC_CHECK_LIB(
  vanessa_adt,
  vanessa_queue_create,
  true,
AC_MSG_ERROR(
""
"**********************************************************************"
"* perdition requires the vanessa_adt abstract data type library"
"* available from"
"* http://www.vergenet.net/linux/vanessa/download/vanessa_adt/ and mirrors."
"**********************************************************************"
),
  -lvanessa_logger
)
AC_CHECK_LIB(
  vanessa_socket,
  vanessa_socket_client_open,
  true,
AC_MSG_ERROR(
""
"**********************************************************************"
"* perdition requires the vanessa_socket TCP socket interface library"
"* available from"
"* http://www.vergenet.net/linux/vanessa/download/vanessa_socket/ and mirrors."
"**********************************************************************"
),
  -lvanessa_logger
)


# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/param.h)


######################################################################
# Libidn

AC_ARG_WITH(libidn, AC_HELP_STRING([--with-libidn=[DIR]],
				   [Support IDN (needs GNU Libidn)]),
	    libidn=$withval, libidn=yes)
if test "$libidn" != "no" ; then
	PKG_CHECK_MODULES(LIBIDN, libidn >= 0.0.0,
			  [libidn=yes], [libidn=no])
fi
if test "$libidn" == "yes" ; then
	AC_DEFINE(WITH_LIBIDN, 1, [Define to 1 if you want Libidn.])
else
AC_MSG_WARN(
""
"************************************************************"
"* Could not find libidn."
"* - SSL may not veify certificates with non-ASCII common names"
"*   or subjectAltName dNSName entries correctly."
"* - Managesieve may not handle non-ascii userames correctly"
"************************************************************"
)
fi

######################################################################
# OpenSSL


AC_MSG_CHECKING([if SSL/TLS support has been disabled]);
AC_ARG_ENABLE(
  ssl,
  [  --disable-ssl           DO not compile with SSL/TLS support.  ],
  [ 
    if test "$enable_ssl" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_ssl="yes";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_ssl" = "yes"; then
AC_ARG_WITH(
  ssl-includes,
  [  --with-ssl-includes=DIR 
                          OpenSSL include files are in DIR.  ],
  [  ssl_includepath="$withval" ],
  [ 
    AC_MSG_CHECKING(OpenSSL include path)
    for ssl_includepath in /usr/openssl/include /usr/local/openssl/include \
        /usr/local/include/openssl /usr/local/ssl/include \
	/usr/include /usr/local/include; do
      if test -f "${ssl_includepath}/openssl/ssl.h"; then
        break
      fi
    done
    AC_MSG_RESULT($ssl_includepath)
  ]
)

ssl_includes="-I$ssl_includepath"

AC_ARG_WITH(
  ssl-libraries,
  [  --with-ssl-libraries=DIR 
                          OpenSSL library files are in DIR.  ],
  [  ssl_libpath="$withval" ],
  [ 
    AC_MSG_CHECKING(OpenSSL library path)
    for ssl_libpath in /usr/openssl/lib64 /usr/openssl/lib \
		/usr/local/openssl/lib64 /usr/local/openssl/lib \
		/usr/lib64/openssl /usr/lib/openssl \
		/usr/local/lib64/openssl /usr/local/lib/openssl \
		/usr/local/ssl/lib64 /usr/local/ssl/lib \
		/usr/lib64 /usr/lib \
		/usr/local/lib64 /usr/local/lib; do
      if test -f "${ssl_libpath}/libssl.a" -o -f "${ssl_libpath}/libssl.so" 
      then
        break
      fi
    done
    AC_MSG_RESULT($ssl_libpath)
  ]
)

ssl_lib="-L$ssl_libpath -lssl -lcrypto"
fi

if test "$enable_ssl" = "yes"; then
AC_CHECK_FILE(
  $ssl_includepath/openssl/ssl.h,
  true,
  [ 
AC_MSG_WARN(
""
"**********************************************************************"
"* SSL/TLS will not be built"
"**********************************************************************"
) ;\
      sleep 5
    enable_ssl="no";
  ]
)
fi
  
if test "$enable_ssl" = "yes"; then
AC_CHECK_LIB(
  ssl,
  ERR_error_string,
  true,
  [ 
AC_MSG_WARN(
""
"**********************************************************************"
"* SSL/TLS will not be built"
"**********************************************************************"
) ;\
      sleep 5
    enable_ssl="no";
  ],
  $ssl_lib
)
fi

if test "$enable_ssl" = "yes"; then
   AC_DEFINE(WITH_SSL_SUPPORT, 1, Compile with SSL/TLS support)
else
  ssl_lib=""
  ssl_includes=""
fi

AC_SUBST(ssl_lib)
AC_SUBST(ssl_includes)
AM_CONDITIONAL(SSL_BUILD, test "${enable_ssl}" = "yes")


######################################################################
# MySQL

AC_MSG_CHECKING([if MySQL support has been disabled]);
AC_ARG_ENABLE(
  mysql,
  [  --disable-mysql         DO not compile with MySQL support.  ],
  [ 
    if test "$enable_mysql" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_mysql="yes";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_mysql" = "yes"; then
AC_ARG_WITH(
  mysql-includes,
  [  --with-mysql-includes=DIR  
                          MySQL include files are in DIR.  ],
  [ mysql_includepath="$withval" ],
  [ 
    AC_MSG_CHECKING(MySQL include path)
    for mysql_includepath in /usr/mysql/include /usr/local/mysql/include \
        /usr/include/mysql /usr/local/include/mysql \
	/usr/local/mysql/include/mysql /usr/include /usr/local/include; do
      if test -f "${mysql_includepath}/mysql.h"; then
        break
      fi
    done
    AC_MSG_RESULT($mysql_includepath)
  ]
)
mysql_includes="-I$mysql_includepath"
fi

if test "$enable_mysql" = "yes"; then
AC_ARG_WITH(
  mysql-libraries,
  [  --with-mysql-libraries=DIR 
                          MySQL library files are in DIR.  ],
  [  mysql_libpath="$withval" ],
  [ 
    AC_MSG_CHECKING(MySQL include path)
    for mysql_libpath in /usr/mysql/lib64 /usr/mysql/lib \
		/usr/local/mysql/lib64 /usr/local/mysql/lib \
		/usr/lib64/mysql /usr/lib/mysql \
		/usr/local/lib64/mysql /usr/local/lib/mysql \
		/usr/local/mysql/lib64/mysql /usr/local/mysql/lib/mysql \
		/usr/lib64 /usr/lib \
		/usr/local/lib64 /usr/local/lib; do
      if test -f "${mysql_libpath}/libmysqlclient.a" \
      	-o -f "${mysql_libpath}/libmysqlclient.so"; then
        break
      fi
    done
    AC_MSG_RESULT($mysql_libpath)
  ]
)
mysql_libs="-lvanessa_logger -lvanessa_adt -L$mysql_libpath -lmysqlclient"
fi

if test "$enable_mysql" = "yes"; then
AC_CHECK_FILE(
  $mysql_includepath/mysql.h, ,
  [ 
    enable_mysq="no" 
AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_mysql will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)
fi

if test "$enable_mysql" = "yes"; then
AC_CHECK_LIB(
  mysqlclient,
  mysql_real_connect,
  true,
  [ 
    enable_mysql="no" 
AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_mysql will not be built: $mysql_libraries"
"**********************************************************************"
) ;\
    sleep 5
  ],
  $mysql_libs
)
fi

AM_CONDITIONAL(MYSQL_BUILD, test "${enable_mysql}" = "yes")


######################################################################
# ODBC

AC_MSG_CHECKING([if ODBC support has been disabled]);
AC_ARG_ENABLE(
  odbc,
  [  --disable-odbc          DO not compile with ODBC support.  ],
  [ 
    if test "$enable_odbc" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_odbc="yes";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_odbc" = "yes"; then
AC_ARG_WITH(
  odbc-includes,
  [  --with-odbc-includes=DIR  
                          ODBC include files are in DIR.  ],
  [ odbc_includepath="$withval" ],
  [ 
    AC_MSG_CHECKING(ODBC include path)
    for odbc_includepath in /usr/odbc/include /usr/local/odbc/include \
        /usr/include/odbc /usr/local/include/odbc \
	/usr/local/odbc/include/odbc /usr/include /usr/local/include ; do
      if test -f "${odbc_includepath}/sql.h" ; then
        break
      fi
    done
    AC_MSG_RESULT($odbc_includepath)
  ]
)
odbc_includes="-I$odbc_includepath"
fi

if test "$enable_odbc" = "yes"; then
AC_ARG_WITH(
  odbc-libraries,
  [  --with-odbc-libraries=DIR 
                          ODBC library files are in DIR.  ],
  [  odbc_libpath="$withval" ],
  [ 
    AC_MSG_CHECKING(ODBC include path)
    for odbc_libpath in /usr/odbc/lib64 /usr/odbc/lib \
		/usr/local/odbc/lib64 /usr/local/odbc/lib \
		/usr/lib64/odbc /usr/lib/odbc \
		/usr/local/lib64/odbc /usr/local/lib/odbc \
		/usr/local/odbc/lib64/odbc /usr/local/odbc/lib/odbc \
		/usr/lib64 /usr/lib \
		/usr/local/lib64 /usr/local/lib ; do
      if test -f "${odbc_libpath}/libodbc.so" ; then
        break
      fi
    done
    AC_MSG_RESULT($odbc_libpath)
  ]
)
odbc_libs="-lvanessa_logger -lvanessa_adt -L$odbc_libpath -lodbc"
fi

if test "$enable_odbc" = "yes"; then
AC_CHECK_FILES(
  $odbc_includepath/sql.h $odbc_includepath/sqlext.h $odbc_includepath/sqltypes.h,
  AC_DEFINE(WITH_UNIX_ODBC, 1, Use unixodbc ODBC Manager),
  enable_odbc="no" 
)
fi

if test "$enable_odbc" = "yes"; then
	AC_CHECK_LIB(odbc, SQLSetEnvAttr, true, 
		[ enable_odbc="no" ], $odbc_libs)
fi

if test "$enable_odbc" != "yes"; then
AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_odbc will not be built: $odbc_libraries"
"* There a many ODBC Managers available including UnixODBC"
"* which is available from www.unixodbc.org"
"**********************************************************************"
) ;\
    sleep 5
fi

AM_CONDITIONAL(ODBC_BUILD, test "${enable_odbc}" = "yes")


######################################################################
# PostgreSQL

AC_MSG_CHECKING([if PostgreSQL support has been disabled]);
AC_ARG_ENABLE(
  pg,
  [  --disable-pg            DO not compile with PostgreSQL support.  ],
  [ 
    if test "$enable_pg" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_pg="yes";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_pg" = "yes"; then
  AC_CHECK_PROGS(PG_CONFIG, pg_config)
  if test "X$PG_CONFIG" = "X"; then
    enable_pg="no" 
    AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_postgresql will not be built"
"**********************************************************************"
)
    sleep 5
  fi
fi

AM_CONDITIONAL(PG_BUILD, test "${enable_pg}" = "yes")

if test "$enable_pg" = "yes"; then
	pg_libdir=-L`$PG_CONFIG --libdir`
	AC_SUBST(pg_libdir)
	pg_includedir=-I`$PG_CONFIG --includedir`
	AC_SUBST(pg_includedir)
fi

######################################################################
# CDB

AC_MSG_CHECKING([if CDB support has been disabled]);
AC_ARG_ENABLE(
  cdb,
  [  --disable-cdb           DO not compile with CDB support.  ],
  [
    if test "$enable_cdb" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [
    enable_cdb="yes";
    AC_MSG_RESULT("no")
  ]
)

if test "$enable_cdb" = "yes"; then
AC_CHECK_HEADERS(
  cdb.h, ,
  [
    enable_cdb="no",
    AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_cdb will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)
fi

if test "$enable_cdb" = "yes"; then
AC_CHECK_LIB(
  cdb,
  cdb_bread,
  true,
  [
    enable_cdb="no",
    AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_cdb will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)
fi

AM_CONDITIONAL(CDB_BUILD, test "${enable_cdb}" = "yes")


######################################################################
# GDBM

AC_MSG_CHECKING([if GDBM support has been disabled]);
AC_ARG_ENABLE(
  gdbm,
  [  --disable-gdbm          DO not compile with GDBM support.  ],
  [ 
    if test "$enable_gdbm" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_gdbm="yes";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_gdbm" = "yes"; then
AC_CHECK_HEADERS(
  gdbm.h, ,
  [
    enable_gdbm="no",
    AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_gdbm and makegdbm will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)
fi

if test "$enable_gdbm" = "yes"; then
AC_CHECK_LIB(
  gdbm, 
  gdbm_fetch, 
  true,
  [ 
    enable_gdbm="no",
    AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_gdbm and makegdbm will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)
fi

AM_CONDITIONAL(GDBM_BUILD, test "${enable_gdbm}" = "yes")


######################################################################
# BerkeleyDB


AC_MSG_CHECKING([if Berkeley DB support has been disabled]);
AC_ARG_ENABLE(
  bdb,
  [  --disable-bdb           DO not compile with Berkeley DB support.  ],
  [ 
    if test "$enable_bdb" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_bdb="yes";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_bdb" = "yes"; then
AC_CHECK_HEADERS(
  db.h, ,
  [
    enable_bdb="no" 
    AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_bdb and makebdb will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)
fi

if test "$enable_bdb" = "yes"; then
AC_CHECK_LIB(
  db,
  db_create, ,
  [
    enable_bdb="no"
AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_bdb and makebdb will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)
fi

AM_CONDITIONAL(BDB_BUILD, test "${enable_bdb}" = "yes")

if test "$enable_bdb" = "yes"; then
	AC_MSG_CHECKING([If BDB db->open() takes 7 arguments]);
	AC_TRY_COMPILE(
		[ #include <db.h> ],
		[ DB *dbp;
		  db_create(&dbp, NULL, 0);
		  dbp->open(NULL, NULL, NULL, NULL, 0, 0, 0); ],
		AC_MSG_RESULT("yes")
		AC_DEFINE(HAVE_BDB_OPEN_7, 1,
			    [BDB db->open() takes 7 arguments]),
		AC_MSG_RESULT("no"))
fi


######################################################################
# NIS

AC_MSG_CHECKING([if NIS support has been disabled]);
AC_ARG_ENABLE(
  nis,
  [  --disable-nis           DO not compile with NIS support.  ],
  [ 
    if test "$enable_nis" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_nis="yes";
    AC_MSG_RESULT("no") 
  ]
)

AM_CONDITIONAL(NIS_BUILD, test "${enable_nis}" = "yes")


######################################################################
# Posix Regular Expression

AC_MSG_CHECKING([if Posix Regular Expression support has been disabled]);
AC_ARG_ENABLE(
  posix_regex,
  [  --disable-posix-regex   DO not compile with Posix Regular Expression support.],
  [ 
    if test "$enable_posix_regex" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_posix_regex="yes";
    AC_MSG_RESULT("no") 
  ]
)

AM_CONDITIONAL(POSIX_REGEX_BUILD, test "${enable_posix_regex}" = "yes")


######################################################################
# Open LDAP

AC_MSG_CHECKING([if LDAP support has been disabled]);
AC_ARG_ENABLE(
  ldap,
  [  --disable-ldap          DO not compile with LDAP support.  ],
  [ 
    if test "$enable_ldap" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_ldap="yes";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_ldap" = "yes"; then
AC_ARG_WITH(
  ldap-includes,
  [  --with-ldap-includes=DIR  
                          Open LDAP include files are in DIR.  ],
  [ 
    if test "$withval" = "no"; then 
     enable_ldap="no"; 
    else
      ldap_includepath="$withval" 
    fi
  ],
  [ 
    AC_MSG_CHECKING(OpenLDAP include path)
    for ldap_includepath in /usr/openldap/include /usr/local/openldap/include \
        /usr/include/openldap /usr/local/include/openldap \
    	/usr/include /usr/local/include; do
      if test -f "${ldap_includepath}/ldap.h"; then
        break
      fi
    done
    AC_MSG_RESULT($ldap_includepath)
  ]
)
ldap_includes="-I$ldap_includepath"
fi

if test "$enable_ldap" = "yes"; then
AC_ARG_WITH(
  ldap-libraries,
  [  --with-ldap-libraries=DIR 
                          Open LDAP library files are in DIR.  ],
  [ 
    if test "$withval" = "no"; then 
     enable_ldap="no"; 
    else
      ldap_libpath="$withval" 
    fi
  ],
  [ 
    AC_MSG_CHECKING(OpenLDAP library path)
    for ldap_libpath in /usr/openldap/lib64 /usr/openldap/lib \
		/usr/local/openldap/lib64 /usr/local/openldap/lib \
		/usr/lib64/openldap /usr/lib/openldap \
		/usr/local/lib64/openldap /usr/local/lib/openldap \
		/usr/lib64 /usr/lib \
		/usr/local/lib64 /usr/local/lib; do
      if test -f "${ldap_libpath}/libldap.a" \
      	-o -f "${ldap_libpath}/libldap.so"; then
        break
      fi
    done
    AC_MSG_RESULT($ldap_libpath)
  ]
)
ldap_libs="-L$ldap_libpath -lldap -llber"
fi

if test "$enable_ldap" = "yes"; then
	AC_CHECK_FILE($ldap_includepath/ldap.h, , [ enable_ldap="no" ])
fi

if test "$enable_ldap" = "yes"; then
	AC_CHECK_LIB(ldap, ldap_url_parse, true, 
		[ enable_ldap="no" ], $ldap_libs)
fi

if test "$enable_ldap" = "yes"; then
	AC_CHECK_MEMBER(LDAPURLDesc.lud_exts,
		AC_DEFINE(WITH_LDAP_LUD_EXTS, 1, Compile with LDAP lud_exts),
		AC_MSG_WARN(
""
"************************************************************"
"* Password and Username support will not be built in the"
"* LDAP module. For Password and Username support compile"
"* openldap2. Available from openldap.org"
"************************************************************"
		),
		[ #include <stdlib.h>
		  #include <lber.h>
		  #include <ldap.h> ])
fi

if test "$enable_ldap" = "yes"; then
        AC_CHECK_LIB(ldap, ldap_set_option, 
	AC_DEFINE(WITH_LDAP_SET_OPTION, 1, Compile with LDAP set_option),
AC_MSG_WARN(
""
"************************************************************"
"* Cannot expicitly set network timeout or ldap protocol"
"* version. For ldap_set_option support please use openlap2."
"* Available from openldap.org"
"************************************************************"
),)
fi

if test "$enable_ldap" = "yes"; then
AC_ARG_WITH(
  ldap-schema-directory,
  [  --with-ldap-schema-directory=DIR 
                          Open LDAP schema files are in DIR.  ],
  [ 
    if test "$withval" = "no"; then 
     ldap_schemadir=""; 
    else
      ldap_schemadir="$withval" 
    fi
  ],
  [ 
    AC_MSG_CHECKING(OpenLDAP schema path)
    for ldap_schemadir in /etc/openldap/schema /etc/ldap/schema \
        /usr/local/openldap/etc/schema; do
      if test -f "${ldap_schemadir}/openldap.schema"; then
        break
      fi
      ldap_schemadir="Not found"
    done
    AC_MSG_RESULT($ldap_schemadir)
    if test "$ldap_schemadir" = "Not found"; then
AC_MSG_WARN(
""
"************************************************************"
"* Could not find OpenLDAP schema directory."
"* perdition.schema will not be installed"
"************************************************************"
)
      ldap_schemadir=""
    fi
  ]
)
fi
AM_CONDITIONAL(LDAP_SCHEMA, test "${ldap_schemadir}X" != "X")

if test "$enable_ldap" != "yes"; then
AC_MSG_WARN(
""
"**********************************************************************"
"* perditiondb_ldap will not be built"
"**********************************************************************"
) ;\
    sleep 5;
fi

AM_CONDITIONAL(LDAP_BUILD, test "${enable_ldap}" = "yes")


######################################################################
# Daemon Map

AC_MSG_CHECKING([if deamon map has been disabled]);
AC_ARG_ENABLE(
  daemon_map,
  [  --disable-daemon-map    DO not compile with daemon map.  ],
  [ 
    if test "$enable_daemon_map" = "no"; then
      AC_MSG_RESULT("yes")
    else
      AC_MSG_RESULT("no")
    fi
  ],
  [ 
    enable_daemon_map="yes";
    AC_MSG_RESULT("no") 
  ]
)

AM_CONDITIONAL(DEAMON_MAP_BUILD, test "${enable_daemon_map}" = "yes")


######################################################################
# PAM

pam=yes
AC_CHECK_HEADERS(
  security/pam_appl.h, 
  true,
  [
    pam=no
AC_MSG_WARN(
""
"**********************************************************************"
"* pam support will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ]
)

if test $pam = yes; then
AC_CHECK_HEADERS(security/pam_misc.h)

AC_CHECK_LIB(
  pam,
  pam_authenticate,
  true,
  [ 
    pam=no
AC_MSG_WARN(
""
"**********************************************************************"
"* pam support will not be built"
"**********************************************************************"
) ;\
    sleep 5
  ],
  $dl_lib
)
fi

if test "$pam" = "yes"; then
  pam_lib="-lpam"
  AC_DEFINE(WITH_PAM_SUPPORT, 1, Compile with PAM support)
else
  pam_lib=""
fi

AM_CONDITIONAL(PAM_BUILD, test "$pam" = "yes")


posix_regex_libs="-lvanessa_logger -lvanessa_adt"

######################################################################
# User and Group to run as

AC_ARG_WITH(
  user,
  [  --with-user=USER        Run perdition as USER. [default=nobody]  ],
  [ perdition_user="$withval" ],
  [ perdition_user="nobody" ],
)
AC_DEFINE_UNQUOTED(WITH_USER, "$perdition_user", User to run perdition as )


AC_ARG_WITH(
  group,
  [  --with-group=GROUP      Run perdition as GROUP. [default=nobody]  ],
  [ perdition_group="$withval" ],
  [ perdition_group="nobody" ],
)
AC_DEFINE_UNQUOTED(WITH_GROUP, "$perdition_group", Group to run perdition as )


######################################################################
# Dmalloc debugging
 
dmalloc_lib=""
AC_ARG_WITH(
  dmalloc,
  [  --with-dmalloc          Compile with dmalloc debugging  ],
  [ dmalloc_lib="-ldmalloc" 
    AC_SUBST(dmalloc_lib) 
    AC_DEFINE(WITH_DMALLOC, 1, Should we use DMALLOC) ],
  
)

AC_MSG_CHECKING([if ldap (latex) documentation is disabled]);
AC_ARG_ENABLE(
  ldap_doc,
  [  --enable-ldap-doc       Create ldap (latex) documentation.  ],
  [ 
    if test "$enable_ldap_doc" = "no"; then
      AC_MSG_RESULT("no")
    else
      AC_MSG_RESULT("yes")
    fi
  ],
  [ 
    enable_ldap_doc="no";
    AC_MSG_RESULT("no") 
  ]
)

if test "$enable_ldap_doc" = "yes"; then
AC_CHECK_PROG(latex, latex, y, n)
AC_CHECK_PROG(dvips, dvips, y, n)
AC_CHECK_PROG(ps2pdf, ps2pdf, y, n)
AC_CHECK_PROG(gunzip, gunzip, y, n)
if test "$latex" = "n" -o "$dvips" = "n" -o "$ps2pdf" = "n" -o "$gunzip" = "n"
then
AC_MSG_WARN(
""
"**********************************************************************"
"* Latex not installed. LDAP documentation will not be built"
"**********************************************************************"
);
else
	ldap_doc_build="yes"
fi
fi
AM_CONDITIONAL(LDAP_DOC_BUILD, test "${ldap_doc_build}" = "yes")


######################################################################
# Check for various argv[] replacing functions on various OSs
#
# Borrowed from Proftpd
# Proftpd is Licenced under the terms of the GNU General Public Licence
# and is available from http://www.proftpd.org/

AC_CHECK_FUNCS(setproctitle)
AC_CHECK_HEADERS(libutil.h)
AC_CHECK_LIB(util, setproctitle,
	[AC_DEFINE(HAVE_SETPROCTITLE, 1, Have setproctiltle)
		ac_cv_func_setproctitle="yes" ; LIBS="$LIBS -lutil"])

if test "$ac_cv_func_setproctitle" = "yes"; then
  AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_NONE, Argv Type)
else
  pf_argv_set="no"

  AC_CHECK_HEADERS(sys/pstat.h,have_pstat_h="yes",have_pstat_h="no")
  if test "$have_pstat_h" = "yes"; then
    AC_CHECK_FUNCS(pstat)
    
    if test "$ac_cv_func_pstat" = "yes"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_PSTAT, Argv Type)
    else
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_WRITABLE, Argv Type)
    fi

    pf_argv_set="yes"
  fi

  if test "$pf_argv_set" = "no"; then
    AC_EGREP_HEADER([#define.*PS_STRINGS.*],sys/exec.h,
			have_psstrings="yes",have_psstrings="no")
    if test "$have_psstrings" = "yes"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_PSSTRINGS, Argv Type)
	pf_argv_set="yes"
    fi
  fi

  if test "$pf_argv_set" = "no"; then
    AC_CACHE_CHECK(whether __progname and __progname_full are available,
		    pf_cv_var_progname,
		    AC_TRY_LINK([extern char *__progname, *__progname_full;],
			[__progname = "foo"; __progname_full = "foo bar";],
			pf_cv_var_progname="yes", pf_cv_var_progname="no"))

    if test "$pf_cv_var_progname" = "yes"; then
	AC_DEFINE(HAVE___PROGNAME, 1, Have __progname)
    fi

    AC_CACHE_CHECK(which argv replacement method to use,
		    pf_cv_argv_type,
		    AC_EGREP_CPP(yes,[
#if defined(__GNU_HURD__)
  yes
#endif
  ],pf_cv_argv_type="new", pf_cv_argv_type="writeable"))

    if test "$pf_cv_argv_type" = "new"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_NEW, Argv Type)
	pf_argv_set="yes"
    fi

    if test "$pf_argv_set" = "no"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_WRITEABLE, Argv Type)
    fi
  fi
fi

  
# End of tests borrowed from Proftpd

######################################################################
#      Check the size of the integer types
#      So we can have integers of known sizes as needed

AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_TYPE_SIGNAL
AC_FUNC_WAIT3
AC_CHECK_FUNCS(select socket strdup strerror parse_printf_format flim)

AC_SUBST(odbc_libs)
AC_SUBST(odbc_includes)
AC_SUBST(mysql_libs)
AC_SUBST(mysql_includes)
AC_SUBST(ldap_libs)
AC_SUBST(ldap_includes)
AC_SUBST(ldap_schemadir)
AC_SUBST(posix_regex_libs)
AC_SUBST(socket_lib)
AC_SUBST(dl_lib)
AC_SUBST(nsl_lib)
AC_SUBST(resolv_lib)
AC_SUBST(crypt_lib)
AC_SUBST(pam_lib)
AC_SUBST(dmalloc_lib)

AC_OUTPUT(
debian/Makefile 
perdition.spec
perdition/Makefile 
perdition/db/Makefile 
perdition/db/cdb/Makefile
perdition/db/gdbm/Makefile 
perdition/db/bdb/Makefile 
perdition/db/posix_regex/Makefile 
perdition/db/mysql/Makefile 
perdition/db/nis/Makefile 
perdition/db/postgresql/Makefile 
perdition/db/ldap/Makefile 
perdition/db/ldap/doc/Makefile 
perdition/db/odbc/Makefile 
perdition/db/daemon/Makefile 
perdition/db/daemon/lib/Makefile 
makegdbm/Makefile 
makebdb/Makefile 
etc/Makefile 
etc/pam.d/Makefile 
etc/perdition/Makefile 
etc/perdition/Makefile.popmap
etc/rc.d/Makefile 
etc/rc.d/init.d/Makefile 
etc/rc.d/init.d/perdition.debian 
etc/rc.d/init.d/perdition.rh 
etc/sysconfig/Makefile 
Makefile
INSTALL
)
