/**********************************************************************
 * options.h                                                   May 1999
 * Horms                                             horms@vergenet.net
 *
 * Read in command line options
 * Code based on man getopt(3), later translated to libpopt.
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2002  Horms
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

#ifndef PERDITION_OPT_STIX
#define PERDITION_OPT_STIX

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>   /*For u_int32_t */
#include <vanessa_adt.h>
#include <popt.h>
#include <jain.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef PERDITION_SYSCONFDIR
#define PERDITION_SYSCONFDIR "/usr/local/etc/perdition"
#endif

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
#define SSL_MODE_EMPTY         0x0    /* 00000 */
#define SSL_MODE_NONE          0x10   /* 10000 */
#define SSL_MODE_SSL_LISTEN    0x1    /* 00001 */
#define SSL_MODE_SSL_OUTGOING  0x2    /* 00010 */
#define SSL_MODE_SSL_ALL       0x3    /* 00011 (SSL_OUTGOING|SSL_LISTEN) */
#define SSL_MODE_TLS_LISTEN    0x4    /* 00100 */
#define SSL_MODE_TLS_OUTGOING  0x8    /* 01000 */
#define SSL_MODE_TLS_ALL       0xc    /* 01100 (TLS_OUTGOING|TLS_LISTEN) */
 
#define SSL_LISTEN_MASK        0x5    /* 00101 (SSL_LISTEN|TLS_LISTEN) */
#define SSL_OUTGOING_MASK      0xa   /* 10010 (SSL_OUTGOING|TLS_OUTGOING) */

#define SSL_SSL_MASK           SSL_MODE_SSL_ALL
#define SSL_TLS_MASK           SSL_MODE_TLS_ALL


#define DEFAULT_ADD_DOMAIN                   STATE_NONE
#ifdef WITH_PAM_SUPPORT
#define DEFAULT_AUTHENTICATE_IN              0
#endif /* WITH_PAM_SUPPORT */
#define DEFAULT_BIND_ADDRESS                 NULL
#define DEFAULT_CLIENT_SERVER_SPECIFICATION  0
#define DEFAULT_CONFIG_FILE              \
  PERDITION_SYSCONFDIR "/perdition.conf"
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
#define DEFAULT_INETD_MODE                   0
#define DEFAULT_MAP_LIB \
  PERDITION_LIBDIR "/libperditiondb_gdbm.so.0"
#define DEFAULT_LOG_FACILITY                 "mail"
#define DEFAULT_LOWER_CASE                   STATE_NONE
#define DEFAULT_MAP_LIB_OPT                  NULL
#define DEFAULT_NO_BIND_BANNER               0
#define DEFAULT_NO_DAEMON                    0
#define DEFAULT_NO_LOOKUP                    0
#define DEFAULT_OUTGOING_SERVER              NULL
#define DEFAULT_PROTOCOL                     PROTOCOL_POP3
#define DEFAULT_STRIP_DOMAIN                 STATE_NONE
#define DEFAULT_SERVER_OK_LINE               0
#define DEFAULT_TIMEOUT                      1800 /*in seconds*/
#ifdef WITH_USER
#define DEFAULT_USERNAME                     WITH_USER
#else
#define DEFAULT_USERNAME                     "nobody"
#endif /* WITH_USER */
#define DEFAULT_USERNAME_FROM_DATABASE       0
#define DEFAULT_QUERY_KEY                    NULL
#define DEFAULT_QUIET                        0
#ifdef WITH_SSL_SUPPORT
#define DEFAULT_SSL_CA_FILE                  \
  PERDITION_SYSCONFDIR "/perdition.ca.pem"
#define DEFAULT_SSL_CERT_FILE                \
  PERDITION_SYSCONFDIR "/perdition.crt.pem"
#define DEFAULT_SSL_KEY_FILE                 \
  PERDITION_SYSCONFDIR "/perdition.key.pem"
#define DEFAULT_SSL_MODE                     SSL_MODE_EMPTY
#define DEFAULT_SSL_LISTEN_CIPHERS           NULL
#define DEFAULT_SSL_OUTGOING_CIPHERS         NULL
#define DEFAULT_SSL_NO_CN_VERIFY             0
#endif /* WITH_SSL_SUPPORT */


typedef struct {
  int             add_domain;
#ifdef WITH_PAM_SUPPORT
  int             authenticate_in;
#endif /* WITH_PAM_SUPPORT */
  char            *bind_address;
  char            *capability;
  char            *mangled_capability;
  int             client_server_specification;
  char            *config_file;
  int             connection_limit;
  int             connection_logging;
  int             connect_relog;
  int             debug;
  char            *domain_delimiter;
  int             domain_delimiter_length;
  char            *group;
  int             inetd_mode;
  char            *pop_capability;
  char            *listen_port;
  char            *log_facility;
  int             lower_case;
  char            *map_library;
  char            *map_library_opt;
  int             no_bind_banner;
  int             no_daemon;
  int             no_lookup;
  char            *outgoing_port;
  vanessa_dynamic_array_t *outgoing_server;
  int             protocol;
  int             quiet;
  int             server_ok_line;
  int             strip_domain;
  int             timeout;
  char            *username;
  int             username_from_database;
  vanessa_dynamic_array_t *query_key;
  flag_t          mask;
#ifdef WITH_SSL_SUPPORT
  char            *ssl_ca_file;
  char            *ssl_cert_file;
  char            *ssl_key_file;
  int             ssl_mode;
  char            *ssl_listen_ciphers;
  char            *ssl_outgoing_ciphers;
  int             ssl_no_cn_verify;
  flag_t          ssl_mask;
#endif /* WITH_SSL_SUPPORT */
} options_t;

/* options_t.mask entries */
#define MASK_ADD_DOMAIN                  (flag_t) 0x00000001
#ifdef WITH_PAM_SUPPORT
#define MASK_AUTHENTICATE_IN             (flag_t) 0x00000002
#endif /* WITH_PAM_SUPPORT */
#define MASK_BIND_ADDRESS                (flag_t) 0x00000004
#define MASK_CAPABILITY                  (flag_t) 0x00000008
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
#define MASK_LISTEN_PORT                 (flag_t) 0x00004000
#define MASK_LOWER_CASE                  (flag_t) 0x00008000
#define MASK_MAP_LIB                     (flag_t) 0x00010000
#define MASK_MAP_LIB_OPT                 (flag_t) 0x00020000
#define MASK_NO_BIND_BANNER              (flag_t) 0x00040000
#define MASK_NO_DAEMON                   (flag_t) 0x00080000
#define MASK_NO_LOOKUP                   (flag_t) 0x00100000
#define MASK_OUTGOING_PORT               (flag_t) 0x00200000
#define MASK_OUTGOING_SERVER             (flag_t) 0x00400000
#define MASK_PROTOCOL                    (flag_t) 0x00800000
#define MASK_SERVER_OK_LINE              (flag_t) 0x01000000
#define MASK_STRIP_DOMAIN                (flag_t) 0x02000000
#define MASK_TIMEOUT                     (flag_t) 0x04000000
#define MASK_USERNAME                    (flag_t) 0x08000000
#define MASK_USERNAME_FROM_DATABASE      (flag_t) 0x10000000
#define MASK_QUERY_KEY                   (flag_t) 0x20000000
#define MASK_QUIET                       (flag_t) 0x40000000

#ifdef WITH_SSL_SUPPORT
/* options_t.ssl_mask entries */
#define MASK_SSL_CA_FILE                 (flag_t) 0x00000001
#define MASK_SSL_CERT_FILE               (flag_t) 0x00000002
#define MASK_SSL_KEY_FILE                (flag_t) 0x00000004
#define MASK_SSL_MODE                    (flag_t) 0x00000008
#define MASK_SSL_LISTEN_CIPHERS          (flag_t) 0x00000010
#define MASK_SSL_OUTGOING_CIPHERS        (flag_t) 0x00000020
#define MASK_SSL_NO_CN_VERIFY            (flag_t) 0x00000040
#endif /* WITH_SSL_SUPPORT */

/* 
 * popt keys off the short value returned. But we are running
 * out of short vales, so some poor arguments are long argument
 * only. So as we still have a key, use integer values outside
 * of the values we might use for a short value
 */
#define TAG_CONNECT_RELOG              (int) 128
#define TAG_LOWER_CASE                 (int) 129
#define TAG_NO_DAEMON                  (int) 130
#define TAG_QUERY_KEY                  (int) 131
#define TAG_SSL_CA_FILE                (int) 132
#define TAG_SSL_CERT_FILE              (int) 133
#define TAG_SSL_KEY_FILE               (int) 134
#define TAG_SSL_MODE                   (int) 135
#define TAG_SSL_LISTEN_CIPHERS         (int) 136
#define TAG_SSL_OUTGOING_CIPHERS       (int) 137
#define TAG_SSL_NO_CN_VERIFY           (int) 138


/*Flag values for options()*/
#define OPT_ERR         (flag_t) 0x1  /*Print error to stderr, enable help*/
#define OPT_CLEAR_MASK  (flag_t) 0x2  /*Set mask to 0*/
#define OPT_SET_MASK    (flag_t) 0x4  /*Add to mask as options are set*/
#define OPT_USE_MASK    (flag_t) 0x8  /*Don't accept options in the mask*/
#define OPT_SET_DEFAULT (flag_t) 0x10 /*Reset options to defaults before
                                           reading options passed*/
#define OPT_FILE        (flag_t) 0x20 /*Reading an options file*/
#define OPT_NOT_SET     (flag_t) 0x40 /*Option is not set, don't free*/
#define OPT_LIT         (flag_t) 0x80 /*Option is a litteral, don't free
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
 * options_set_mask
 * Set the options mask
 * pre: mask: pointer to current mask that may be modified
 *      mask_entry: value to or with opt->mask
 *      flag: flags
 * post: mask is added if flags permit
 * return: 1 if mask is added
 *         0 otherwise
 **********************************************************************/

int options_set_mask(flag_t *mask, flag_t mask_entry, flag_t flag);


/**********************************************************************
 * log_options
 * Log options
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
