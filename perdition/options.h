/**********************************************************************
 * options.h                                                   May 1999
 * Horms                                             horms@verge.net.au
 *
 * Read in command line options
 * Code based on man getopt(3), later translated to libpopt.
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2005  Horms
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

#ifndef PERDITION_OPT_STIX
#define PERDITION_OPT_STIX

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>   /*For u_int32_t */
#include <vanessa_adt.h>
#include <popt.h>

#include "managesieve_write.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef PERDITION_SYSCONFDIR
#define PERDITION_SYSCONFDIR "/usr/local/etc/perdition"
#endif

#ifndef PERDITION_LOCALSTATEDIR
#define PERDITION_LOCALSTATEDIR "/usr/local/var"
#endif

#define PERDITION_PID_DIR PERDITION_LOCALSTATEDIR "/run"

#include "log.h"
#include "protocol.h"
#include "str.h"
#include "server_port.h"

#define OPT_SERVER_DELIMITER                ','
#define OPT_KEY_DELIMITER                   ','

/*
 * States for strip_domain option which may be the logical
 * or of these.
 */

#define STATE_NONE         0x0
#define STATE_GET_SERVER   0x1
#define STATE_LOCAL_AUTH   0x2
#define STATE_REMOTE_LOGIN 0x4
#define STATE_ALL          \
  (STATE_GET_SERVER|STATE_LOCAL_AUTH|STATE_REMOTE_LOGIN)


/*
 * States for ssl_mode option which may be the logical
 * or of these.
 * 
 */
#define SSL_MODE_EMPTY         0x00   /* 0000000 */
#define SSL_MODE_NONE          0x40   /* 1000000 */
#define SSL_MODE_SSL_LISTEN    0x01   /* 0000001 */
#define SSL_MODE_SSL_OUTGOING  0x02   /* 0000010 */
#define SSL_MODE_SSL_ALL       0x03   /* 0000011 (SSL_OUTGOING|SSL_LISTEN) */
#define SSL_MODE_TLS_LISTEN    0x04   /* 0000100 */
#define SSL_MODE_TLS_OUTGOING  0x08   /* 0001000 */
#define SSL_MODE_TLS_ALL       0x0c   /* 0001100 (TLS_OUTGOING|TLS_LISTEN) */
#define SSL_MODE_TLS_LISTEN_FORCE \
	                       0x10   /* 0010000 */
#define SSL_MODE_TLS_OUTGOING_FORCE \
			       0x20   /* 0100000 */
#define SSL_MODE_TLS_ALL_FORCE 0x30   /* 0110000 (SSL_MODE_TLS_LISTEN_FORCE|
					       SSL_MODE_TLS_OUTGOING_FORCE) */
 
#define SSL_LISTEN_MASK        0x05   /* 000101 (SSL_LISTEN|TLS_LISTEN) */
#define SSL_OUTGOING_MASK      0x0a   /* 001010 (SSL_OUTGOING|TLS_OUTGOING) */

#define SSL_SSL_MASK           SSL_MODE_SSL_ALL
#define SSL_TLS_MASK           SSL_MODE_TLS_ALL

#define LOG_PASSWD_NEVER       0x00
#define LOG_PASSWD_NEVER_STR   "never"
#define LOG_PASSWD_FAIL        0x01
#define LOG_PASSWD_FAIL_STR    "fail"
#define LOG_PASSWD_OK          0x02
#define LOG_PASSWD_OK_STR      "ok"
#define LOG_PASSWD_ALWAYS      (LOG_PASSWD_FAIL|LOG_PASSWD_OK)
#define LOG_PASSWD_ALWAYS_STR  "always"


#define DEFAULT_ADD_DOMAIN                   STATE_NONE
#define DEFAULT_ADD_DOMAIN_STRIP_DEPTH       1
#ifdef WITH_PAM_SUPPORT
#define DEFAULT_AUTHENTICATE_IN              0
#endif /* WITH_PAM_SUPPORT */
#define DEFAULT_BIND_ADDRESS                 NULL
#define DEFAULT_CLIENT_SERVER_SPECIFICATION  0
#define DEFAULT_CONNECTION_LIMIT             0
#define DEFAULT_CONNECTION_LOGGING           0
#define DEFAULT_CONNECT_RELOG                300
#define DEFAULT_DEBUG                        0
#define DEFAULT_DOMAIN_DELIMITER             "@"
#ifdef WITH_GROUP
#define DEFAULT_GROUP                        WITH_GROUP
#else
#define DEFAULT_GROUP                        "nobody"
#endif /* WITH_GROUP */
#define DEFAULT_IMAP_CAPABILITY              "IMAP4 IMAP4REV1"
#define DEFAULT_INETD_MODE                   0
#define DEFAULT_MAP_LIB                      PERDITION_LIBDIR \
			                     "/libperditiondb_gdbm.so.0"
#define DEFAULT_LOG_FACILITY                 "mail"
#define DEFAULT_LOGIN_DISABLED               0
#define DEFAULT_LOWER_CASE                   STATE_NONE
#define DEFAULT_MANAGESIEVE_CAPABILITY       MANAGESIEVE_DEFAULT_CAPA
#define DEFAULT_MAP_LIB_OPT                  NULL
#define DEFAULT_NO_BIND_BANNER               0
#define DEFAULT_NO_DAEMON                    0
#define DEFAULT_NO_LOOKUP                    0
#define DEFAULT_TCP_KEEPALIVE                0
#define DEFAULT_OUTGOING_SERVER              NULL
#define DEFAULT_OK_LINE                      "You are so in"
#define DEFAULT_POP_CAPABILITY               "UIDL.USER"
#define DEFAULT_PROTOCOL                     PROTOCOL_POP3
#define DEFAULT_STRIP_DOMAIN                 STATE_NONE
#define DEFAULT_SERVER_RESP_LINE             0
#define DEFAULT_TIMEOUT                      1800 /*in seconds*/
#define DEFAULT_AUTHENTICATE_TIMEOUT         DEFAULT_TIMEOUT
#ifdef WITH_USER
#define DEFAULT_USERNAME                     WITH_USER
#else
#define DEFAULT_USERNAME                     "nobody"
#endif /* WITH_USER */
#define DEFAULT_USERNAME_FROM_DATABASE       0
#define DEFAULT_QUERY_KEY                    NULL
#define DEFAULT_QUIET                        0
#define DEFAILT_LOG_PASSWD                   LOG_PASSWD_NEVER
#ifdef WITH_SSL_SUPPORT
#define DEFAULT_SSL_CA_CHAIN_FILE            NULL
#define RECOMMENDED_SSL_CA_CHAIN_FILE         PERDITION_SYSCONFDIR \
					     "/perdition.ca.pem"
#define DEFAULT_SSL_CA_FILE                  NULL
#define RECOMMENDED_SSL_CA_FILE               PERDITION_SYSCONFDIR \
                                             "/perdition.ca.pem"
#define DEFAULT_SSL_CA_PATH                  PERDITION_SYSCONFDIR \
                                             "/perdition.ca/"
#define DEFAULT_SSL_CA_ACCEPT_SELF_SIGNED    0
#define DEFAULT_SSL_CERT_FILE                PERDITION_SYSCONFDIR \
					     "/perdition.crt.pem"
#define DEFAULT_SSL_DH_PARAMS_FILE           NULL
#define DEFAULT_SSL_CERT_ACCEPT_EXPIRED      0
#define DEFAULT_SSL_CERT_ACCEPT_SELF_SIGNED  0
#define DEFAULT_SSL_CERT_ACCEPT_NOT_YET_VALID 0
#define DEFAULT_SSL_CERT_VERIFY_DEPTH        9 /* Same as openssl's default */
#define DEFAULT_SSL_KEY_FILE                 PERDITION_SYSCONFDIR \
					     "/perdition.key.pem"
#define DEFAULT_SSL_MODE                     SSL_MODE_EMPTY
#define DEFAULT_SSL_LISTEN_CIPHERS           NULL
#define DEFAULT_SSL_OUTGOING_CIPHERS         NULL
#define DEFAULT_SSL_NO_CERT_VERIFY           0
#define DEFAULT_SSL_NO_CLIENT_CERT_VERIFY    0
#define DEFAULT_SSL_NO_CN_VERIFY             0
#define DEFAULT_SSL_PASSPHRASE_FD            0
#define DEFAULT_SSL_PASSPHRASE_FILE          NULL
#define DEFAULT_SSL_LISTEN_MIN_PROTO_VERSION "tlsv1"
#define DEFAULT_SSL_OUTGOING_MIN_PROTO_VERSION "tlsv1"
#define DEFAULT_SSL_LISTEN_MAX_PROTO_VERSION NULL
#define DEFAULT_SSL_OUTGOING_MAX_PROTO_VERSION NULL
#endif /* WITH_SSL_SUPPORT */


typedef struct {
  int             add_domain;
  unsigned int    add_domain_strip_depth;
#ifdef WITH_PAM_SUPPORT
  int             authenticate_in;
#endif /* WITH_PAM_SUPPORT */
  int             authenticate_timeout;
  vanessa_dynamic_array_t *bind_address;
  char            *pop_capability;
  char            *managesieve_capability;
  char            *imap_capability;
  int             client_server_specification;
  char            *config_file;
  int             connection_limit;
  int             connection_logging;
  int             connect_relog;
  int             debug;
  char            *domain_delimiter;
  int             domain_delimiter_length;
  char            *explicit_domain;
  char            *group;
  int             inetd_mode;
  char            *listen_port;
  char            *log_facility;
  int             log_passwd;
  int             login_disabled;
  int             lower_case;
  char            *map_library;
  char            *map_library_opt;
  int             no_bind_banner;
  int             no_daemon;
  int             no_lookup;
  int             tcp_keepalive;
  char            *outgoing_port;
  vanessa_dynamic_array_t *outgoing_server;
  char            *ok_line;
  char            *pid_file;
  int             protocol;
  int             quiet;
  int             server_resp_line;
  int             strip_domain;
  int             timeout;
  char            *username;
  int             username_from_database;
  vanessa_dynamic_array_t *query_key;
  flag_t          mask;
  flag_t          mask2;
  char            *ssl_ca_chain_file;
  char            *ssl_ca_file;
  char            *ssl_ca_path;
  int             ssl_ca_accept_self_signed;
  char            *ssl_cert_file;
  char            *ssl_dh_params_file;
  int             ssl_cert_accept_self_signed;
  int             ssl_cert_accept_expired;
  int             ssl_cert_accept_not_yet_valid;
  int             ssl_cert_verify_depth;
  char            *ssl_key_file;
  int             ssl_mode;
  char            *ssl_listen_ciphers;
  char            *ssl_outgoing_ciphers;
  int             ssl_no_cert_verify;
  int             ssl_no_client_cert_verify;
  int             ssl_no_cn_verify;
  int             ssl_passphrase_fd;
  char            *ssl_passphrase_file;
  char            *ssl_listen_min_proto_version;
  char            *ssl_outgoing_min_proto_version;
  char            *ssl_listen_max_proto_version;
  char            *ssl_outgoing_max_proto_version;
  flag_t          ssl_mask;
} options_t;

/* options_t.mask entries */
#define MASK_ADD_DOMAIN                  (flag_t) 0x00000001
#ifdef WITH_PAM_SUPPORT
#define MASK_AUTHENTICATE_IN             (flag_t) 0x00000002
#endif /* WITH_PAM_SUPPORT */
#define MASK_BIND_ADDRESS                (flag_t) 0x00000004
#define MASK_CONNECTION_LIMIT            (flag_t) 0x00000010
#define MASK_CONNECTION_LOGGING          (flag_t) 0x00000020
#define MASK_CONNECT_RELOG               (flag_t) 0x00000040
#define MASK_DEBUG                       (flag_t) 0x00000080
#define MASK_DOMAIN_DELIMITER            (flag_t) 0x00000100
#define MASK_CLIENT_SERVER_SPECIFICATION (flag_t) 0x00000200
#define MASK_CONFIG_FILE                 (flag_t) 0x00000400
#define MASK_GROUP                       (flag_t) 0x00000800
#define MASK_INETD_MODE                  (flag_t) 0x00001000
#define MASK_LOG_FACILITY                (flag_t) 0x00002000
#define MASK_LOGIN_DISABLED              (flag_t) 0x00004000
#define MASK_LISTEN_PORT                 (flag_t) 0x00008000
#define MASK_LOWER_CASE                  (flag_t) 0x00010000
#define MASK_MAP_LIB                     (flag_t) 0x00020000
#define MASK_MAP_LIB_OPT                 (flag_t) 0x00040000
#define MASK_NO_BIND_BANNER              (flag_t) 0x00080000
#define MASK_NO_DAEMON                   (flag_t) 0x00100000
#define MASK_NO_LOOKUP                   (flag_t) 0x00200000
#define MASK_OUTGOING_PORT               (flag_t) 0x00400000
#define MASK_OUTGOING_SERVER             (flag_t) 0x00800000
#define MASK_PROTOCOL                    (flag_t) 0x01000000
#define MASK_SERVER_RESP_LINE            (flag_t) 0x02000000
#define MASK_STRIP_DOMAIN                (flag_t) 0x04000000
#define MASK_TIMEOUT                     (flag_t) 0x08000000
#define MASK_USERNAME                    (flag_t) 0x10000000
#define MASK_USERNAME_FROM_DATABASE      (flag_t) 0x20000000
#define MASK_QUERY_KEY                   (flag_t) 0x40000000
#define MASK_QUIET                       (flag_t) 0x80000000

#define MASK2_OK_LINE                    (flag_t) 0x00000001
#define MASK2_PID_FILE                   (flag_t) 0x00000002
#define MASK2_EXPLICIT_DOMAIN            (flag_t) 0x00000004
#define MASK2_LOG_PASSWD                 (flag_t) 0x00000008
#define MASK2_AUTHENTICATE_TIMEOUT       (flag_t) 0x00000010
#define MASK2_IMAP_CAPABILITY            (flag_t) 0x00000020
#define MASK2_MANAGESIEVE_CAPABILITY     (flag_t) 0x00000040
#define MASK2_POP_CAPABILITY             (flag_t) 0x00000080
#define MASK2_TCP_KEEPALIVE              (flag_t) 0x00000100

#ifdef WITH_SSL_SUPPORT
/* options_t.ssl_mask entries */
#define MASK_SSL_CA_CHAIN_FILE                 (flag_t) 0x00000001
#define MASK_SSL_CA_FILE                       (flag_t) 0x00000002
#define MASK_SSL_CA_PATH                       (flag_t) 0x00000004
#define MASK_SSL_CA_ACCEPT_SELF_SIGNED         (flag_t) 0x00000008
#define MASK_SSL_CERT_FILE                     (flag_t) 0x00000010
#define MASK_SSL_CERT_ACCEPT_EXPIRED           (flag_t) 0x00000020
#define MASK_SSL_CERT_ACCEPT_NOT_YET_VALID     (flag_t) 0x00000040
#define MASK_SSL_CERT_ACCEPT_SELF_SIGNED       (flag_t) 0x00000080
#define MASK_SSL_CERT_VERIFY_DEPTH             (flag_t) 0x00000100
#define MASK_SSL_KEY_FILE                      (flag_t) 0x00000200
#define MASK_SSL_MODE                          (flag_t) 0x00000400
#define MASK_SSL_LISTEN_CIPHERS                (flag_t) 0x00000800
#define MASK_SSL_OUTGOING_CIPHERS              (flag_t) 0x00000800
#define MASK_SSL_NO_CERT_VERIFY                (flag_t) 0x00001000
#define MASK_SSL_NO_CLIENT_CERT_VERIFY         (flag_t) 0x00003000
#define MASK_SSL_NO_CN_VERIFY                  (flag_t) 0x00004000
#define MASK_SSL_PASSPHRASE_FD                 (flag_t) 0x00008000
#define MASK_SSL_PASSPHRASE_FILE               (flag_t) 0x00010000
#define MASK_SSL_DH_PARAMS_FILE                (flag_t) 0x00020000
#define MASK_SSL_LISTEN_MIN_PROTO_VERSION      (flag_t) 0x00040000
#define MASK_SSL_OUTGOING_MIN_PROTO_VERSION    (flag_t) 0x00080000
#define MASK_SSL_LISTEN_MAX_PROTO_VERSION      (flag_t) 0x00100000
#define MASK_SSL_OUTGOING_MAX_PROTO_VERSION    (flag_t) 0x00200000
#endif /* WITH_SSL_SUPPORT */

/* 
 * popt keys off the short value returned. But we are running
 * out of short vales, so some poor arguments are long argument
 * only. So as we still have a key, use integer values outside
 * of the values we might use for a short value
 */
#define TAG_CONNECT_RELOG                      (int) 128
#define TAG_LOGIN_DISABLED                     (int) 129
#define TAG_LOWER_CASE                         (int) 130
#define TAG_NO_DAEMON                          (int) 131
#define TAG_QUERY_KEY                          (int) 132
#define TAG_PID_FILE                           (int) 133
#define TAG_LOG_PASSWD                         (int) 134
#define TAG_SSL_CA_CHAIN_FILE                  (int) 135
#define TAG_SSL_CA_FILE                        (int) 136
#define TAG_SSL_CA_PATH                        (int) 137
#define TAG_SSL_CA_ACCEPT_SELF_SIGNED          (int) 138
#define TAG_SSL_CERT_FILE                      (int) 139
#define TAG_SSL_CERT_ACCEPT_EXPIRED            (int) 140
#define TAG_SSL_CERT_ACCEPT_SELF_SIGNED        (int) 141
#define TAG_SSL_CERT_ACCEPT_NOT_YET_VALID      (int) 142
#define TAG_SSL_CERT_VERIFY_DEPTH              (int) 143
#define TAG_SSL_KEY_FILE                       (int) 144
#define TAG_SSL_MODE                           (int) 145
#define TAG_SSL_LISTEN_CIPHERS                 (int) 146
#define TAG_SSL_OUTGOING_CIPHERS               (int) 147
#define TAG_SSL_NO_CERT_VERIFY                 (int) 148
#define TAG_SSL_NO_CLIENT_CERT_VERIFY          (int) 149
#define TAG_SSL_NO_CN_VERIFY                   (int) 150
#define TAG_AUTHENTICATE_TIMEOUT               (int) 151
#define TAG_SSL_PASSPHRASE_FD                  (int) 152
#define TAG_SSL_PASSPHRASE_FILE                (int) 153
#define TAG_IMAP_CAPABILITY                    (int) 154
#define TAG_MANAGESIEVE_CAPABILITY             (int) 155
#define TAG_POP_CAPABILITY                     (int) 156
#define TAG_TCP_KEEPALIVE                      (int) 157
#define TAG_SSL_DH_PARAMS_FILE                 (int) 158
#define TAG_SSL_LISTEN_MIN_PROTO_VERSION       (int) 159
#define TAG_SSL_OUTGOING_MIN_PROTO_VERSION     (int) 160
#define TAG_SSL_LISTEN_MAX_PROTO_VERSION       (int) 161
#define TAG_SSL_OUTGOING_MAX_PROTO_VERSION     (int) 162

/*Flag values for options()*/
#define OPT_ERR         (flag_t) 0x1  /*Print error to stderr, enable help*/
#define OPT_CLEAR_MASK  (flag_t) 0x2  /*Set mask to 0*/
#define OPT_SET_MASK    (flag_t) 0x4  /*Add to mask as options are set*/
#define OPT_USE_MASK    (flag_t) 0x8  /*Don't accept options in the mask*/
#define OPT_SET_DEFAULT (flag_t) 0x10 /*Reset options to defaults before
                                           reading options passed*/
#define OPT_FILE        (flag_t) 0x20 /*Reading an options file*/
#define OPT_NOT_SET     (flag_t) 0x40 /*Option is not set, don't free*/
#define OPT_LIT         (flag_t) 0x80 /*Option is a literal, don't free
                                            or copy, over-rides OPT_SET*/

#define OPT_FIRST_CALL  (flag_t) \
 OPT_ERR|OPT_CLEAR_MASK|OPT_SET_MASK|OPT_SET_DEFAULT

/**********************************************************************
 * options
 * Read in command line options
 * pre: argc: number or elements in argv
 *      argv: array of strings with command line-options
 *      flag: see options.h for flag values
 *            ignores errors otherwise
 * post: global opt is seeded with values according to argc and argv
 **********************************************************************/

int options(int argc, char **argv, flag_t f);


/**********************************************************************
 * log_options_str_free
 * Free return value of log_options_str()
 * pre: a: array of strings to free
 * post: a is freed
 * return: none
 **********************************************************************/

void log_options_str_free(char **a);


/**********************************************************************
 * log_options_str
 * Log options to a null-terminated array of strings
 * pre: global opt is set
 * post: options are logged to a
 *       Caller must free strings in a using log_options_str_free()
 * return: 0 on success
 *         1 on error
 **********************************************************************/


char **log_options_str(void);


/**********************************************************************
 * log_options
 * Log options to the active vanessa logger
 * pre: str: string to log options to
 *      len: number of bytes in str
 *      global opt is set
 *      vanessa logger has been set (else nothing will happen)
 * post: options are logged to the active vanessa logger
 * return: 0 on success
 *         1 on error
 **********************************************************************/

int log_options(void);


/**********************************************************************
 * usage
 * Display usage information
 * pre: exit_status: status to exit programme with
 * post: Usage information is displayed stdout if exit_status=0, stderr
 *       otherwise.
 *       Programme exits with exit status.
 * return: does not return
 **********************************************************************/

void usage(int exit_status);


/**********************************************************************
 * split_str_server_port
 * Split a string into substrings on a delimiter and store
 * in server_port_structures in a dynamic array
 * pre: str: string to split
 *      delimiter: character to split string on
 * post: string is split. 
 *       Note: The string is modified.
 * return: dynamic array containing server_port structures
 *         NULL on error
 *         string being NULL is an error state
 **********************************************************************/

vanessa_dynamic_array_t *split_str_server_port(
  char *string, 
  const char delimiter
);


#endif /* PERDITION_OPT_STIX */
