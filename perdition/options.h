/**********************************************************************
 * options.h                                                   May 1999
 * Horms                                             horms@vergenet.net
 *
 * Read in command line options
 * Code based on man getopt(3), later translated to libpopt.
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
#define PERDITION_SYSCONFDIR "/usr/local/etc/perdition/"
#endif

#include "log.h"
#include "protocol.h"
#include "daemon.h"
#include "str.h"
#include "server_port.h"

#define OPT_SERVER_DELIMITER                ','

#ifdef WITH_PAM_SUPPORT
#define DEFAULT_AUTHENTICATE_IN              0
#endif /* WITH_PAM_SUPPORT */
#define DEFAULT_BIND_ADDRESS                 NULL
#define DEFAULT_CLIENT_SERVER_SPECIFICATION  0
#define DEFAULT_CONFIG_FILE              PERDITION_SYSCONFDIR "/perdition.conf"
#define DEFAULT_CONNECTION_LIMIT             0
#define DEFAULT_CONNECTION_LOGGING           0
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
#define DEFAULT_MAP_LIB_OPT                  NULL
#define DEFAULT_NO_BIND_BANNER               0
#define DEFAULT_NO_LOOKUP                    0
#define DEFAULT_OUTGOING_SERVER              NULL
#define DEFAULT_PROTOCOL                     PROTOCOL_POP3
#define DEFAULT_STRIP_DOMAIN                 0
#define DEFAULT_SERVER_OK_LINE               0
#define DEFAULT_TIMEOUT                      1800 /*in seconds*/
#ifdef WITH_USER
#define DEFAULT_USERNAME                     WITH_USER
#else
#define DEFAULT_USERNAME                     "nobody"
#endif /* WITH_USER */
#define DEFAULT_QUIET                        0

typedef struct {
#ifdef WITH_PAM_SUPPORT
  int             authenticate_in;
#endif /* WITH_PAM_SUPPORT */
  char            *bind_address;
  int             client_server_specification;
  char            *config_file;
  int             connection_limit;
  int             connection_logging;
  int             debug;
  char            *domain_delimiter;
  int             domain_delimiter_length;
  char            *group;
  int             inetd_mode;
  int             timeout;
  char            *listen_port;
  char            *log_facility;
  char            *map_library;
  char            *map_library_opt;
  int             no_bind_banner;
  int             no_lookup;
  char            *outgoing_port;
  vanessa_dynamic_array_t *outgoing_server;
  int             protocol;
  int             quiet;
  int             server_ok_line;
  int             strip_domain;
  char            *username;
  flag_t          mask;
} options_t;

/*options_t.mask entries*/
#ifdef WITH_PAM_SUPPORT
#define MASK_AUTHENTICATE_IN             (flag_t) 0x00000001
#endif /* WITH_PAM_SUPPORT */
#define MASK_BIND_ADDRESS                (flag_t) 0x00000002
#define MASK_CONNECTION_LIMIT            (flag_t) 0x00000004
#define MASK_CONNECTION_LOGGING          (flag_t) 0x00000008
#define MASK_DEBUG                       (flag_t) 0x00000010
#define MASK_DOMAIN_DELIMITER            (flag_t) 0x00000020
#define MASK_CLIENT_SERVER_SPECIFICATION (flag_t) 0x00000040
#define MASK_CONFIG_FILE                 (flag_t) 0x00000080
#define MASK_GROUP                       (flag_t) 0x00000100
#define MASK_INETD_MODE                  (flag_t) 0x00000200
#define MASK_LOG_FACILITY                (flag_t) 0x00000400
#define MASK_LISTEN_PORT                 (flag_t) 0x00000800
#define MASK_MAP_LIB                     (flag_t) 0x00001000
#define MASK_MAP_LIB_OPT                 (flag_t) 0x00002000
#define MASK_NO_BIND_BANNER              (flag_t) 0x00004000
#define MASK_NO_LOOKUP                   (flag_t) 0x00008000
#define MASK_OUTGOING_PORT               (flag_t) 0x00010000
#define MASK_OUTGOING_SERVER             (flag_t) 0x00020000
#define MASK_PROTOCOL                    (flag_t) 0x00040000
#define MASK_SERVER_OK_LINE              (flag_t) 0x00080000
#define MASK_STRIP_DOMAIN                (flag_t) 0x00100000
#define MASK_TIMEOUT                     (flag_t) 0x00200000
#define MASK_USERNAME                    (flag_t) 0x00400000
#define MASK_QUIET                       (flag_t) 0x00800000

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

int options(int argc, char **argv, flag_t flag);
int options_set_mask(flag_t *mask, flag_t flag, flag_t mask_entry);
int log_options(void);
void usage(int exit_status);
vanessa_dynamic_array_t *split_str_server_port(char *string, const char delimiter);

#endif
