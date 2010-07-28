/**********************************************************************
 * options.c                                             September 1999
 * Horms                                             horms@verge.net.au
 *
 * Read in command line options
 * Code based on man getopt(3), later translated to popt
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/utsname.h>

#include "options.h"
#include "config_file.h"
#include "perdition_globals.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define USAGE_ERROR_SLEEP 3


options_t opt;


/**********************************************************************
 * log_passwd_to_str
 * Get the string value of a log_passwd mode
 * pre: x: integer mode
 * return: mode string
 *         NULL on error
 **********************************************************************/

static const char *
log_passwd_to_str(int x)
{
	switch(x){
      		case LOG_PASSWD_NEVER:
	      		return LOG_PASSWD_NEVER_STR;
      		case LOG_PASSWD_OK:
	      		return LOG_PASSWD_OK_STR;
      		case LOG_PASSWD_FAIL:
			return LOG_PASSWD_FAIL_STR;
      		case LOG_PASSWD_ALWAYS:
			return LOG_PASSWD_ALWAYS_STR;
	}
	return NULL;
}


/**********************************************************************
 * log_passwd_from_str
 * Get the integer value of a log_passwd mode
 * pre: str: string mode
 * return: mode integer
 *         -1 on error
 **********************************************************************/

static int
log_passwd_from_str(const char *str)
{
	if (!strcasecmp(str, LOG_PASSWD_NEVER_STR))
		return LOG_PASSWD_NEVER;
	else if (!strcasecmp(str, LOG_PASSWD_FAIL_STR))
		return LOG_PASSWD_FAIL;
	else if (!strcasecmp(str, LOG_PASSWD_OK_STR))
		return LOG_PASSWD_OK;
	else if (!strcasecmp(str, LOG_PASSWD_ALWAYS_STR))
		return LOG_PASSWD_ALWAYS;
	return -1;
}

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

static int 
options_set_mask(flag_t *mask, flag_t mask_entry, flag_t flag)
{
  if(flag&OPT_USE_MASK && (*mask)&mask_entry) return(0);
  if(flag&OPT_SET_MASK) (*mask)|=mask_entry;
  return(1);
}


/***********************************************************************
 * opt_p
 * Assign an option that is a char *
 * pre: opt: option to assign
 *      value: value to copy into opt
 *      mask:  current option mask
 *      mask_entry: entry of this option in the option mask
 *      flag:  flags as per options.h
 * post: If the mask and options allow as per options_set_mask()
 *       value is copied into opt. Any existing value of opt is freed
 *       The mask may also be altered as per options_set_mask()
 *       Else no change.
 ***********************************************************************/

static void
opt_p(char **opt, const char *value, 
		flag_t *mask, flag_t mask_entry, flag_t flag)
{
      	if (!options_set_mask(mask, mask_entry, flag))
      		return;
  	if (!((flag)&OPT_NOT_SET) && *opt != NULL)
		free(*opt); 
	*opt = (!value) ? NULL : strdup(value);
}


/***********************************************************************
 * opt_i
 * Assign an option that is an int
 * pre: opt: option to assign
 *      value: value to assign to opt
 *      mask:  current option mask
 *      mask_entry: entry of this option in the option mask
 *      flag:  flags as per options.h
 * post: If the mask and options allow as per options_set_mask()
 *       value is assigned to opt. 
 *       The mask may also be altered as per options_set_mask()
 *       Else no change.
 ***********************************************************************/

static void
opt_i(int *opt, int value, flag_t *mask, flag_t mask_entry, flag_t flag)
{
      	if (options_set_mask(mask, mask_entry, flag))
		*opt = value;
}


/***********************************************************************
 * opt_i_or
 * Assign an option that is an int
 * The value assigned will be the logical or of the current value 
 * of the option, and the value paramater
 * pre: opt: option to assign
 *      value: value to assign to opt
 *      mask:  current option mask
 *      mask_entry: entry of this option in the option mask
 *      flag:  flags as per options.h
 * post: If the mask and options allow as per options_set_mask()
 *       value is assigned to opt. 
 *       The mask may also be altered as per options_set_mask()
 *       Else no change.
 ***********************************************************************/

static void
opt_i_or(int *opt, int value, flag_t *mask, flag_t mask_entry, flag_t flag)
{
	opt_i(opt, *opt|value, mask, mask_entry, flag);
}

/***********************************************************************
 * opt_da
 * Assign an option that is a vanessa_dynamic_array *
 * pre: opt: option to assign
 *      value: value to copy into opt
 *      mask:  current option mask
 *      mask_entry: entry of this option in the option mask
 *      flag:  flags as per options.h
 * post: If the mask and options allow as per options_set_mask()
 *       value is assigned to opt.ss. Any existing value of opt is freed
 *       The mask may also be altered as per options_set_mask()
 *       Else no change.
 ***********************************************************************/

static void
opt_da(vanessa_dynamic_array_t **opt, vanessa_dynamic_array_t *value, 
		flag_t *mask, flag_t mask_entry, flag_t flag)
{
	if (!options_set_mask(mask, mask_entry, flag))
		return;
	if (!((flag)&OPT_NOT_SET) && *opt != NULL)
		vanessa_dynamic_array_destroy(*opt);
	*opt = value;
}

static int
opt_err(flag_t f, poptContext context)
{
	poptFreeContext(context);

	if (f&OPT_ERR)
		usage(-1); /* Exits */

	return -1; 
}

static int
opt_err_digit(flag_t f, poptContext context, const char *opt)
{
	VANESSA_LOGGER_ERR_RAW_UNSAFE("Parameter to %s must be "
				      "a positive integer", opt);
	return opt_err(f, context);
}

#define OPT_MODIFY_USERNAME(opt, mask, mask_entry, flag, id_str) \
  if(strcasecmp(optarg_copy, "all")==0){ \
    opt_i_or(&opt, STATE_ALL, &mask, mask_entry, flag); \
  } \
  else if( \
    strcasecmp(optarg_copy, "servername_lookup")==0 || \
    strcasecmp(optarg_copy, "server_lookup")==0 \
  ){ \
    opt_i_or(&opt, STATE_GET_SERVER, &mask, mask_entry, flag); \
  } \
  else if( \
    strcasecmp(optarg_copy, "local_authentication")==0 || \
    strcasecmp(optarg_copy, "local_auth")==0 \
  ){ \
    opt_i_or(&opt, STATE_LOCAL_AUTH, &mask, mask_entry, flag); \
  } \
  else if(strcasecmp(optarg_copy, "remote_login")==0){ \
    opt_i_or(&opt, STATE_REMOTE_LOGIN, &mask, mask_entry, flag); \
  } \
  else { \
    VANESSA_LOGGER_ERR_UNSAFE("unknown state for %s: %s", id_str, optarg_copy); \
    if(f&OPT_ERR) { \
      usage(-1); \
    } \
  }

#define OPT_STRIP_DOMAIN \
  OPT_MODIFY_USERNAME(opt.strip_domain, opt.mask, MASK_STRIP_DOMAIN, f, \
    "strip_domain");

#define OPT_ADD_DOMAIN							\
	if (vanessa_socket_str_is_digit(optarg_copy)) {			\
		opt.add_domain_strip_depth = atoi(optarg_copy);		\
	}								\
	else {								\
		OPT_MODIFY_USERNAME(opt.add_domain, opt.mask, 		\
				MASK_ADD_DOMAIN, f, "add_domain");	\
	}

#define OPT_LOWER_CASE \
  OPT_MODIFY_USERNAME(opt.lower_case, opt.mask, MASK_LOWER_CASE, f, \
    "lower_case");

#define OPTARG_DUP \
  if(optarg==NULL){ \
    VANESSA_LOGGER_DEBUG("OPTARG_DUP: optarg is NULL"); \
    if(f&OPT_ERR) vanessa_socket_daemon_exit_cleanly(-1); \
  } \
  if((optarg_copy=strdup(optarg)) == NULL){ \
    VANESSA_LOGGER_DEBUG_ERRNO("strdup"); \
    if(f&OPT_ERR) vanessa_socket_daemon_exit_cleanly(-1); \
  }



#ifdef WITH_SSL_SUPPORT
#define OPT_SSL_MODE \
  { \
    int new=0; \
    int all=0; \
    if(strcasecmp(optarg_copy, "none")==0){ \
       new=SSL_MODE_NONE; \
    } \
    else if(strcasecmp(optarg_copy, "ssl_listen")==0){ \
       new=SSL_MODE_SSL_LISTEN; \
    } \
    else if(strcasecmp(optarg_copy, "ssl_outgoing")==0){ \
       new=SSL_MODE_SSL_OUTGOING; \
    } \
    else if(strcasecmp(optarg_copy, "ssl_all")==0){ \
       new=SSL_MODE_SSL_ALL; \
    } \
    else if(strcasecmp(optarg_copy, "tls_listen")==0){ \
       new=SSL_MODE_TLS_LISTEN; \
    } \
    else if(strcasecmp(optarg_copy, "tls_outgoing")==0){ \
       new=SSL_MODE_TLS_OUTGOING; \
    } \
    else if(strcasecmp(optarg_copy, "tls_listen_force")==0){ \
       new=(SSL_MODE_TLS_LISTEN_FORCE|SSL_MODE_TLS_LISTEN); \
    } \
    else if(strcasecmp(optarg_copy, "tls_outgoing_force")==0){ \
       new=(SSL_MODE_TLS_OUTGOING_FORCE|SSL_MODE_TLS_OUTGOING); \
    } \
    else if(strcasecmp(optarg_copy, "tls_all_force")==0){ \
       new=(SSL_MODE_TLS_ALL_FORCE|SSL_MODE_TLS_ALL); \
    } \
    else if(strcasecmp(optarg_copy, "tls_all")==0){ \
       new=SSL_MODE_TLS_ALL; \
    } \
    else { \
     VANESSA_LOGGER_ERR_RAW_UNSAFE("unknown ssl_mode: %s", optarg_copy); \
      if(f&OPT_ERR) { \
        usage(-1); \
      } \
    } \
    \
    all=new|opt.ssl_mode; \
    if( ( ((all&SSL_LISTEN_MASK)==SSL_LISTEN_MASK) || \
          ((all&SSL_OUTGOING_MASK)==SSL_OUTGOING_MASK) ) && \
        ( new!=SSL_MODE_NONE || \
          (opt.ssl_mode!=SSL_MODE_NONE && opt.ssl_mode!=SSL_MODE_EMPTY) ) \
     ){ \
      VANESSA_LOGGER_DEBUG_RAW("invalid ssl_mode combination"); \
      if(f&OPT_ERR) vanessa_socket_daemon_exit_cleanly(-1); \
    } \
    opt_i_or(&(opt.ssl_mode), new, &(opt.ssl_mask), MASK_SSL_MODE, f); \
  }
#else /* WITH_SSL_SUPPORT */
#define NO_SSL_OPT(_opt)                                                     \
      VANESSA_LOGGER_DEBUG_RAW(_opt                                          \
	" is only supported when ssl support is compiled in");               \
      return opt_err(f, context);

#endif /* WITH_SSL_SUPPORT */


/**********************************************************************
 * options
 * Read in command line options
 * pre: argc: number or elements in argv
 *      argv: array of strings with command line-options
 *      flag: see options.h for flag values
 *            ignores errors otherwise
 * post: global opt is seeded with values according to argc and argv
 **********************************************************************/

int options(int argc, char **argv, flag_t f){
  int c=0;
  int index;
  flag_t i;
  const char *optarg;
  const char *basename;
  char *optarg_copy;
  char *end;
  poptContext context;
  const char **trailing_argv;

  static struct poptOption options[] =
  {
    {"add_domain",                  'A',  POPT_ARG_STRING, NULL, 'A',
     NULL, NULL},
    {"authenticate_in",             'a',  POPT_ARG_NONE,   NULL, 'a',
     NULL, NULL},
    {"authenticate_timeout",        '\0', POPT_ARG_STRING, NULL,
     TAG_AUTHENTICATE_TIMEOUT, NULL, NULL},
    {"no_bind_banner",              'B',  POPT_ARG_NONE,   NULL, 'B',
     NULL, NULL},
    {"bind_address",                'b',  POPT_ARG_STRING, NULL, 'b',
     NULL, NULL},
    {"connection_logging",          'C',  POPT_ARG_NONE,   NULL, 'C',
     NULL, NULL},
    {"connect_relog",               '\0', POPT_ARG_STRING, NULL,
      TAG_CONNECT_RELOG, NULL, NULL},
    {"client_server_specification", 'c',  POPT_ARG_NONE,   NULL,
     'c', NULL, NULL},
    {"domain_delimiter",            'D',  POPT_ARG_STRING, NULL,
     'D', NULL, NULL},
    {"debug",                       'd',  POPT_ARG_NONE,   NULL,
     'd', NULL, NULL},
    {"explicit_domain",             'e',  POPT_ARG_STRING, NULL,
     'e', NULL, NULL},
    {"log_facility",                'F',  POPT_ARG_STRING, NULL,
     'F', NULL, NULL},
    {"config_file",                 'f',  POPT_ARG_STRING, NULL,
     'f', NULL, NULL},
    {"group",                       'g',  POPT_ARG_STRING, NULL,
     'g', NULL, NULL},
    {"help",                        'h',  POPT_ARG_NONE,   NULL,
     'h', NULL, NULL},
    {"inetd_mode",                  'i',  POPT_ARG_NONE,   NULL,
     'i', NULL, NULL},
    {"capability",                  'I',  POPT_ARG_STRING, NULL,
     'I', NULL, NULL},
    {"imap_capability",             '\0', POPT_ARG_STRING, NULL,
     TAG_IMAP_CAPABILITY, NULL, NULL},
    {"managesieve_capability",      '\0', POPT_ARG_STRING, NULL,
     TAG_MANAGESIEVE_CAPABILITY, NULL, NULL},
    {"pop_capability",              '\0', POPT_ARG_STRING, NULL,
     TAG_POP_CAPABILITY, NULL, NULL},
    {"connection_limit",            'L',  POPT_ARG_STRING, NULL,
     'L', NULL, NULL},
    {"listen_port",                 'l',  POPT_ARG_STRING, NULL,
     'l', NULL, NULL},
    {"log_passwd",                  '\0', POPT_ARG_STRING, NULL,
      TAG_LOG_PASSWD, NULL, NULL},
    {"map_library",                 'M',  POPT_ARG_STRING, NULL,
     'M', NULL, NULL},
    {"map_library_opt",             'm',  POPT_ARG_STRING, NULL,
     'm', NULL, NULL},
    {"no_lookup",                   'n',  POPT_ARG_NONE,   NULL,
     'n', NULL, NULL},
    {"ok_line",                     'O',  POPT_ARG_STRING, NULL,
     'O', NULL, NULL},
    {"server_ok_line",              '\0', POPT_ARG_NONE,   NULL,
     'o', NULL, NULL},
    {"server_resp_line",            'o',  POPT_ARG_NONE,   NULL,
     'o', NULL, NULL},
    {"protocol",                    'P',  POPT_ARG_STRING, NULL,
     'P', NULL, NULL},
    {"outgoing_port",               'p',  POPT_ARG_STRING, NULL,
     'p', NULL, NULL},
    {"strip_domain",                'S',  POPT_ARG_STRING, NULL,
     'S', NULL, NULL},
    {"outgoing_server",             's',  POPT_ARG_STRING, NULL,
     's', NULL, NULL},
    {"timeout",                     't',  POPT_ARG_STRING, NULL,
     't', NULL, NULL},
    {"username",                    'u',  POPT_ARG_STRING, NULL,
     'u', NULL, NULL},
    {"username_from_database",      'U',  POPT_ARG_NONE,   NULL,
     'U', NULL, NULL},
    {"quiet",                       'q',  POPT_ARG_NONE,   NULL,
     'q', NULL, NULL},
    {"query_key",                   '\0', POPT_ARG_STRING, NULL,
      TAG_QUERY_KEY, NULL, NULL},
    {"login_disabled",              '\0', POPT_ARG_NONE,   NULL,
      TAG_LOGIN_DISABLED, NULL, NULL},
    {"lower_case",                  '\0', POPT_ARG_STRING, NULL,
      TAG_LOWER_CASE, NULL, NULL},
    {"pid_file",                    '\0', POPT_ARG_STRING, NULL,
      TAG_PID_FILE, NULL, NULL},
    {"no_daemon",                   '\0', POPT_ARG_NONE,   NULL,
      TAG_NO_DAEMON, NULL, NULL},
    {"tcp_keepalive",               '\0', POPT_ARG_NONE,   NULL,
      TAG_TCP_KEEPALIVE, NULL, NULL},
    {"ssl_mode",                    '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_MODE, NULL, NULL},
    {"ssl_ca_chain_file",           '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_CA_CHAIN_FILE, NULL, NULL},
    {"ssl_ca_file",                 '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_CA_FILE, NULL, NULL},
    {"ssl_ca_path",                 '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_CA_PATH, NULL, NULL},
    {"ssl_ca_accept_self_signed",   '\0', POPT_ARG_NONE,   NULL,
      TAG_SSL_CA_ACCEPT_SELF_SIGNED, NULL, NULL},
    {"ssl_cert_file",               '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_CERT_FILE, NULL, NULL},
    {"ssl_cert_accept_expired",     '\0', POPT_ARG_NONE,   NULL,
      TAG_SSL_CERT_ACCEPT_EXPIRED, NULL, NULL},
    {"ssl_cert_accept_not_yet_valid", '\0', POPT_ARG_NONE, NULL,
     TAG_SSL_CERT_ACCEPT_NOT_YET_VALID, NULL, NULL},
    {"ssl_cert_accept_self_signed", '\0', POPT_ARG_NONE,   NULL,
      TAG_SSL_CERT_ACCEPT_SELF_SIGNED, NULL, NULL},
    {"ssl_cert_verify_depth",       '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_CERT_VERIFY_DEPTH, NULL, NULL},
    {"ssl_key_file",                '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_KEY_FILE, NULL, NULL},
    {"ssl_listen_ciphers",          '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_LISTEN_CIPHERS, NULL, NULL},
    {"ssl_outgoing_ciphers",        '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_OUTGOING_CIPHERS, NULL, NULL},
    {"ssl_no_cert_verify",          '\0', POPT_ARG_NONE,   NULL,
      TAG_SSL_NO_CERT_VERIFY, NULL, NULL},
    {"ssl_no_client_cert_verify",   '\0', POPT_ARG_NONE,   NULL,
      TAG_SSL_NO_CLIENT_CERT_VERIFY, NULL, NULL},
    {"ssl_no_cn_verify",            '\0', POPT_ARG_NONE,   NULL,
      TAG_SSL_NO_CN_VERIFY, NULL, NULL},
    {"ssl_passphrase_fd",           '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_PASSPHRASE_FD, NULL, NULL},
    {"ssl_passphrase_file",         '\0', POPT_ARG_STRING, NULL,
      TAG_SSL_PASSPHRASE_FILE, NULL, NULL},
    {NULL,                           0,   0,               NULL,
     0, NULL, NULL}
  };

  basename=str_basename(argv[0]);

  if(argc==0 || argv==NULL) return(0);

  /* i is used as a dummy variable */
  if(f&OPT_SET_DEFAULT){
    opt_i(&(opt.add_domain), DEFAULT_ADD_DOMAIN, &i, 0, OPT_NOT_SET);
    opt.add_domain_strip_depth = DEFAULT_ADD_DOMAIN_STRIP_DEPTH;
#ifdef WITH_PAM_SUPPORT
    opt_i(&(opt.authenticate_in), DEFAULT_AUTHENTICATE_IN, &i, 0, OPT_NOT_SET);
#endif /* WITH_PAM_SUPPORT */
    opt_i(&(opt.authenticate_timeout), DEFAULT_AUTHENTICATE_TIMEOUT,
	  &i, 0, OPT_NOT_SET);
    opt_i(&(opt.no_bind_banner), DEFAULT_NO_BIND_BANNER,
		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.client_server_specification), 
		    DEFAULT_CLIENT_SERVER_SPECIFICATION, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.connection_limit), DEFAULT_CONNECTION_LIMIT, 
		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.connection_logging), DEFAULT_CONNECTION_LOGGING,
		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.debug), DEFAULT_DEBUG, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.inetd_mode), DEFAULT_INETD_MODE, &i, 0, OPT_NOT_SET);
    if(!(f&OPT_FILE) && !strcmp("perdition.imap4", basename)){
      opt_i(&(opt.protocol), PROTOCOL_IMAP4, &i, 0, OPT_NOT_SET);
    }
    else if(!(f&OPT_FILE) && !strcmp("perdition.imap4s", basename)){
      opt_i(&(opt.protocol), PROTOCOL_IMAP4S, &i, 0, OPT_NOT_SET);
    }
    else if(!(f&OPT_FILE) && !strcmp("perdition.imaps", basename)){
      opt_i(&(opt.protocol), PROTOCOL_IMAP4S, &i, 0, OPT_NOT_SET);
    }
    else if(!(f&OPT_FILE) && !strcmp("perdition.pop3", basename)){
      opt_i(&(opt.protocol), PROTOCOL_POP3, &i, 0, OPT_NOT_SET);
    }
    else if(!(f&OPT_FILE) && !strcmp("perdition.pop3s", basename)){
      opt_i(&(opt.protocol), PROTOCOL_POP3S, &i, 0, OPT_NOT_SET);
    } else if (!(f&OPT_FILE) && !strcmp("perdition.managesieve", basename)) {
      opt_i(&(opt.protocol), PROTOCOL_MANAGESIEVE, &i, 0, OPT_NOT_SET);
    } else {
      opt_i(&(opt.protocol), DEFAULT_PROTOCOL, &i, 0, OPT_NOT_SET);
    }
    opt_i(&(opt.no_daemon), DEFAULT_NO_DAEMON, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.no_lookup), DEFAULT_NO_LOOKUP, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.tcp_keepalive), DEFAULT_TCP_KEEPALIVE, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.login_disabled), DEFAULT_LOGIN_DISABLED, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.lower_case), DEFAULT_LOWER_CASE, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.server_resp_line), DEFAULT_SERVER_RESP_LINE, 
		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.strip_domain), DEFAULT_STRIP_DOMAIN, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.timeout), DEFAULT_TIMEOUT, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.username_from_database), DEFAULT_USERNAME_FROM_DATABASE, 
   		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.quiet), DEFAULT_QUIET, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.connect_relog), DEFAULT_CONNECT_RELOG, &i, 0, OPT_NOT_SET);
    opt_da(&(opt.bind_address), DEFAULT_BIND_ADDRESS, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.log_facility), DEFAULT_LOG_FACILITY, &i, 0, OPT_NOT_SET);
    if(!(f&OPT_FILE)) {
      char *filename;
      filename = config_file_name(basename, opt.protocol);
      opt_p(&(opt.config_file), filename, &i, 0, OPT_NOT_SET);
    }
    opt_p(&(opt.domain_delimiter), DEFAULT_DOMAIN_DELIMITER, 
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.explicit_domain), NULL, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.group), DEFAULT_GROUP, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.imap_capability), DEFAULT_IMAP_CAPABILITY, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.listen_port), PERDITION_PROTOCOL_DEPENDANT, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.log_passwd), DEFAILT_LOG_PASSWD, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.managesieve_capability), DEFAULT_MANAGESIEVE_CAPABILITY,
          &i, 0, OPT_NOT_SET);
    opt_p(&(opt.map_library), DEFAULT_MAP_LIB, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.map_library_opt), DEFAULT_MAP_LIB_OPT, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.outgoing_port), PERDITION_PROTOCOL_DEPENDANT, 
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ok_line), DEFAULT_OK_LINE, &i, 0, OPT_NOT_SET);

    opt_p(&(opt.username), DEFAULT_USERNAME, &i, 0, OPT_NOT_SET);
    opt_da(&(opt.outgoing_server), DEFAULT_OUTGOING_SERVER, 
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.pop_capability), DEFAULT_POP_CAPABILITY, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.pid_file), PERDITION_PROTOCOL_DEPENDANT,&i, 0, OPT_NOT_SET);
    {
      char *filename;
      filename = malloc(strlen(PERDITION_PID_DIR) + (2*strlen(basename)) + 7);
      if (!filename) {
	      VANESSA_LOGGER_DEBUG_ERRNO("malloc");
	      return -1;
      }
      sprintf(filename, "%s/%s/%s.pid", PERDITION_PID_DIR, basename,
		      basename);
      opt_p(&(opt.pid_file), filename, &i, 0, OPT_NOT_SET);
      free(filename);
    }
    opt_da(&(opt.query_key), DEFAULT_QUERY_KEY, &i, 0, OPT_NOT_SET);
#ifdef WITH_SSL_SUPPORT
    opt_i(&(opt.ssl_mode), DEFAULT_SSL_MODE, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_ca_file), DEFAULT_SSL_CA_FILE, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_ca_path), DEFAULT_SSL_CA_PATH, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_ca_accept_self_signed), DEFAULT_SSL_CA_ACCEPT_SELF_SIGNED, 
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_cert_file), DEFAULT_SSL_CERT_FILE, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_cert_accept_expired), DEFAULT_SSL_CERT_ACCEPT_EXPIRED, 
	       	    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_cert_accept_not_yet_valid), 
		    DEFAULT_SSL_CERT_ACCEPT_NOT_YET_VALID, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_cert_accept_self_signed), 
		    DEFAULT_SSL_CERT_ACCEPT_SELF_SIGNED, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_cert_verify_depth), DEFAULT_SSL_CERT_VERIFY_DEPTH,
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_key_file), DEFAULT_SSL_KEY_FILE, &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_ca_chain_file), DEFAULT_SSL_CA_CHAIN_FILE,
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_listen_ciphers), DEFAULT_SSL_LISTEN_CIPHERS,
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_outgoing_ciphers), DEFAULT_SSL_OUTGOING_CIPHERS,
		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_no_cert_verify), DEFAULT_SSL_NO_CERT_VERIFY,
		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_no_client_cert_verify), DEFAULT_SSL_NO_CLIENT_CERT_VERIFY,
		    &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_no_cn_verify),DEFAULT_SSL_NO_CN_VERIFY, &i, 0, OPT_NOT_SET);
    opt_i(&(opt.ssl_passphrase_fd),DEFAULT_SSL_PASSPHRASE_FD,
		    &i, 0, OPT_NOT_SET);
    opt_p(&(opt.ssl_passphrase_file),DEFAULT_SSL_PASSPHRASE_FILE,
		    &i, 0, OPT_NOT_SET);
#endif /* WITH_SSL_SUPPORT */
  }

  if(f&OPT_CLEAR_MASK){
    opt.mask=(flag_t)0;
#ifdef WITH_SSL_SUPPORT
    opt.ssl_mask=(flag_t)0;
#endif /* WITH_SSL_SUPPORT */
  }

  context= poptGetContext("perdition", argc, 
		  (const char **)argv, options, 0);

  while ((c=poptGetNextOpt(context)) >= 0){
    optarg=poptGetOptArg(context);
    switch (c){
      case 'A':
        OPTARG_DUP;
	while((end=strchr(optarg_copy, ','))!=NULL){
	  *end='\0';
	  OPT_ADD_DOMAIN;
	  optarg_copy=end+1;
	}
	OPT_ADD_DOMAIN;
        break;
      case 'a':
#ifdef WITH_PAM_SUPPORT
        opt_i(&(opt.authenticate_in), 1, &(opt.mask), MASK_AUTHENTICATE_IN, f);
        break;
#else
      VANESSA_LOGGER_DEBUG_RAW(
	"authenticate is only supported when compiled against libpam");
      return opt_err(f, context);
#endif
      case TAG_AUTHENTICATE_TIMEOUT:
        if (!vanessa_socket_str_is_digit(optarg))
	  return opt_err_digit(f, context, "authenticate_timeout");
        opt_i(&(opt.authenticate_timeout), atoi(optarg), &(opt.mask2),
	      MASK2_AUTHENTICATE_TIMEOUT, f);
        break;
      case 'B':
        opt_i(&(opt.no_bind_banner), 1, &(opt.mask), MASK_NO_BIND_BANNER, f);
        break;
      case 'b':
        if(options_set_mask(&(opt.mask), f, MASK_BIND_ADDRESS)){
          if(!(f&OPT_NOT_SET) && opt.bind_address!=NULL) {
            vanessa_dynamic_array_destroy(opt.bind_address);
          }
          OPTARG_DUP;
          opt.bind_address=split_str_server_port(
            optarg_copy,
            OPT_SERVER_DELIMITER
          );
        }
        break;
      case TAG_CONNECT_RELOG:
        if (!vanessa_socket_str_is_digit(optarg))
	  return opt_err_digit(f, context, "connect_relog");
        opt_i(&(opt.connect_relog), atoi(optarg), &(opt.mask), 
			MASK_CONNECT_RELOG, f);
        break;
      case 'C':
        opt_i(&(opt.connection_logging), 1, &(opt.mask), MASK_DEBUG, f);
        break;
      case 'c':
        opt_i(&(opt.client_server_specification), 1, &(opt.mask),
			MASK_CLIENT_SERVER_SPECIFICATION, f);
        break;
      case 'D':
        opt_p(&(opt.domain_delimiter), optarg, &(opt.mask), 
			MASK_DOMAIN_DELIMITER, f);
        break;
      case 'd':
        opt_i(&(opt.debug), 1, &(opt.mask), MASK_DEBUG, f);
        break;
      case 'e':
	opt_p(&(opt.explicit_domain), optarg, &(opt.mask2),
			MASK2_EXPLICIT_DOMAIN, f);
	break;
      case 'f':
        if(!(f&OPT_FILE)){
          opt_p(&(opt.config_file), optarg, &(opt.mask), MASK_CONFIG_FILE, f);
        }
        break;
      case 'F':
        opt_p(&(opt.log_facility), optarg, &(opt.mask), MASK_LOG_FACILITY, f);
        break;
      case 'g':
        opt_p(&(opt.group), optarg, &(opt.mask), MASK_GROUP, f);
        break;
      case 'h':
        if(f&OPT_ERR && !(f&OPT_FILE)){ 
	  usage(0); 
	}
	break;
      case 'I':
	if (options_set_mask(&opt.mask2, MASK2_IMAP_CAPABILITY, f))
	  opt_p(&(opt.imap_capability), optarg, &(opt.mask2),
		MASK2_IMAP_CAPABILITY, f);
	if (options_set_mask(&opt.mask2, MASK2_MANAGESIEVE_CAPABILITY, f))
	  opt_p(&(opt.managesieve_capability), optarg, &(opt.mask2),
		MASK2_MANAGESIEVE_CAPABILITY, f);
	if (options_set_mask(&opt.mask2, MASK2_POP_CAPABILITY, f))
	  opt_p(&(opt.pop_capability), optarg, &(opt.mask2),
		MASK2_POP_CAPABILITY, f);
	break;
      case TAG_IMAP_CAPABILITY:
	opt_p(&(opt.imap_capability), optarg, &(opt.mask2),
	      MASK2_IMAP_CAPABILITY, f);
	break;
      case TAG_MANAGESIEVE_CAPABILITY:
	opt_p(&(opt.managesieve_capability), optarg, &(opt.mask2),
	      MASK2_MANAGESIEVE_CAPABILITY, f);
	break;
      case TAG_POP_CAPABILITY:
	opt_p(&(opt.pop_capability), optarg, &(opt.mask2),
	      MASK2_POP_CAPABILITY, f);
	break;
      case 'i':
        opt_i(&(opt.inetd_mode), 1, &(opt.mask), MASK_INETD_MODE, f);
        break;
      case 'j':
	VANESSA_LOGGER_DEBUG( "Jain, Oath\n"); 
        break;
      case 'L':
        if (!vanessa_socket_str_is_digit(optarg))
	  return opt_err_digit(f, context, "L|connection_limit");
        opt_i(&(opt.connection_limit), atoi(optarg), &(opt.mask),
			MASK_CONNECTION_LIMIT, f);
        break;
      case 'l':
        opt_p(&(opt.listen_port), optarg, &(opt.mask), MASK_LISTEN_PORT, f);
        break;
      case 'M':
        opt_p(&(opt.map_library), optarg, &(opt.mask), MASK_MAP_LIB, f);
        break;
      case 'm':
        opt_p(&(opt.map_library_opt), optarg, &(opt.mask), MASK_MAP_LIB_OPT, f);
        break;
      case 'n':
        opt_i(&(opt.no_lookup), 1, &(opt.mask), MASK_NO_LOOKUP, f);
        break;
      case 'O':
        opt_p(&(opt.ok_line), optarg, &(opt.mask2), MASK2_OK_LINE, f);
        break;
      case 'o':
        opt_i(&(opt.server_resp_line), 1, &(opt.mask),
			MASK_SERVER_RESP_LINE, f);
        break;
      case 'P':
        if((index=protocol_index(optarg))<0){
		VANESSA_LOGGER_ERR_UNSAFE("Unknown protocol: \"%s\"", optarg);
		usage(-1);
        }
        else {
          opt_i(&(opt.protocol), index, &(opt.mask), MASK_PROTOCOL, f);
        }
        break;
      case 'p':
        opt_p(&(opt.outgoing_port), optarg, &(opt.mask), MASK_OUTGOING_PORT, f);
        break;
      case 'S':
        OPTARG_DUP;
	while((end=strchr(optarg_copy, ','))!=NULL){
	  *end='\0';
	  OPT_STRIP_DOMAIN;
	  optarg_copy=end+1;
	}
	OPT_STRIP_DOMAIN;
        break;
      case 's':
        if(options_set_mask(&(opt.mask), f, MASK_OUTGOING_SERVER)){
          if(!(f&OPT_NOT_SET) && opt.outgoing_server!=NULL) {
            vanessa_dynamic_array_destroy(opt.outgoing_server);
          }
          OPTARG_DUP;
          opt.outgoing_server=split_str_server_port(
            optarg_copy,
            OPT_SERVER_DELIMITER
          );
        }
        break;
      case 't':
        if (!vanessa_socket_str_is_digit(optarg))
          return opt_err_digit(f, context, "t|timeout");
        opt_i(&(opt.timeout), atoi(optarg), &(opt.mask), MASK_TIMEOUT, f);
        break;
      case 'u':
        opt_p(&(opt.username), optarg, &(opt.mask), MASK_USERNAME, f);
        break;
      case 'U':
        opt_i(&(opt.username_from_database), 1, &(opt.mask), 
			MASK_USERNAME_FROM_DATABASE, f);
        break;
      case 'q':
        opt_i(&(opt.quiet), 1, &(opt.mask), MASK_QUIET, f);
        break;
      case TAG_NO_DAEMON:
	opt_i(&(opt.no_daemon), 1, &(opt.mask), MASK_NO_DAEMON, f);
        break;
      case TAG_TCP_KEEPALIVE:
	opt_i(&(opt.tcp_keepalive), 1, &(opt.mask2), MASK2_TCP_KEEPALIVE, f);
        break;
      case TAG_LOGIN_DISABLED:
	opt_i(&(opt.login_disabled), 1, &(opt.mask), MASK_LOGIN_DISABLED, f);
        break;
      case TAG_LOWER_CASE:
        OPTARG_DUP;
	while((end=strchr(optarg_copy, ','))!=NULL){
	  *end='\0';
	  OPT_LOWER_CASE;
	  optarg_copy=end+1;
	}
	OPT_LOWER_CASE;
        break;
      case TAG_QUERY_KEY:
        if(options_set_mask(&(opt.mask), f, MASK_QUERY_KEY)){
          if(!(f&OPT_NOT_SET) && opt.query_key!=NULL) {
            vanessa_dynamic_array_destroy(opt.query_key);
          }
          OPTARG_DUP;
          opt.query_key=vanessa_dynamic_array_split_str(
            optarg_copy,
            OPT_KEY_DELIMITER
          );
        }
        break;
      case TAG_PID_FILE:
	if(*optarg && *optarg != '/'){
	  VANESSA_LOGGER_ERR_UNSAFE("Invalid pid file: \"%s\"", optarg);
	  usage(-1);
	}
        opt_p(&(opt.pid_file), optarg, &(opt.mask2), MASK2_PID_FILE, f);
        break;
      case TAG_LOG_PASSWD:
       	opt_i(&(opt.log_passwd), log_passwd_from_str(optarg), 
			&(opt.mask2), MASK2_LOG_PASSWD, f);
	if (opt.log_passwd < 0) {
	       	VANESSA_LOGGER_ERR_UNSAFE("Invalid log_passwd mode: \"%s\"", 
				optarg);
		usage(-1);
	}
	break;
      case TAG_SSL_MODE:
#ifdef WITH_SSL_SUPPORT
        OPTARG_DUP;
	while((end=strchr(optarg_copy, ','))!=NULL){
	  *end='\0';
	  OPT_SSL_MODE;
	  optarg_copy=end+1;
	}
	OPT_SSL_MODE;
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_mode");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CA_FILE:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_ca_file), optarg, &(opt.ssl_mask), MASK_SSL_CA_FILE, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_ca_file");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CA_PATH:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_ca_path), optarg, &(opt.ssl_mask), MASK_SSL_CA_PATH, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_ca_path");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CA_ACCEPT_SELF_SIGNED:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_ca_accept_self_signed), 1, &(opt.ssl_mask),
			MASK_SSL_CA_ACCEPT_SELF_SIGNED, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_ca_accept_self_signed");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CERT_VERIFY_DEPTH:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_cert_verify_depth), atoi(optarg), &(opt.ssl_mask),
			MASK_SSL_CERT_VERIFY_DEPTH, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_ca_verify_depth");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CA_CHAIN_FILE:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_ca_chain_file), optarg, &(opt.ssl_mask),
			MASK_SSL_CA_CHAIN_FILE, f);
#else /* WITH_SSL_SUPPORT */
      NO_SSL_OPT("ssl_ca_chain_file");
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_CERT_FILE:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_cert_file), optarg, &(opt.ssl_mask), 
			MASK_SSL_CERT_FILE, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_cert_file");
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_CERT_ACCEPT_EXPIRED:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_cert_accept_expired), 1, &(opt.ssl_mask),
			MASK_SSL_CERT_ACCEPT_EXPIRED, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_cert_accept_expired");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CERT_ACCEPT_NOT_YET_VALID:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_cert_accept_not_yet_valid), 1, &(opt.ssl_mask),
			MASK_SSL_CERT_ACCEPT_NOT_YET_VALID, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_cert_accept_not_yet_valid");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CERT_ACCEPT_SELF_SIGNED:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_cert_accept_self_signed), 1, &(opt.ssl_mask),
			MASK_SSL_CERT_ACCEPT_SELF_SIGNED, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_cert_accept_self_signed");
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_KEY_FILE:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_key_file), optarg, &(opt.ssl_mask), 
			MASK_SSL_KEY_FILE, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_key_file");
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_LISTEN_CIPHERS:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_listen_ciphers), optarg, &(opt.ssl_mask),
			MASK_SSL_LISTEN_CIPHERS,f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_listen_ciphers");
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_OUTGOING_CIPHERS:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_outgoing_ciphers), optarg, &(opt.ssl_mask),
			MASK_SSL_OUTGOING_CIPHERS, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_outgoing_ciphers");
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_NO_CERT_VERIFY:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_no_cert_verify), 1, &(opt.ssl_mask), 
			MASK_SSL_NO_CERT_VERIFY, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_no_cert_verify");
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_NO_CLIENT_CERT_VERIFY:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_no_client_cert_verify), 1, &(opt.ssl_mask),
			MASK_SSL_NO_CLIENT_CERT_VERIFY, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_no_client_cert_verify");
#endif /* WITH_SSL_SUPPORT */
        break;
      case TAG_SSL_NO_CN_VERIFY:
#ifdef WITH_SSL_SUPPORT
        opt_i(&(opt.ssl_no_cn_verify), 1, &(opt.ssl_mask),
			MASK_SSL_NO_CN_VERIFY, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_no_cn_verify");
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_PASSPHRASE_FD:
#ifdef WITH_SSL_SUPPORT
        if (!vanessa_socket_str_is_digit(optarg))
          return opt_err(f, context);
        opt_i(&(opt.ssl_passphrase_fd), atoi(optarg), &(opt.ssl_mask),
			MASK_SSL_PASSPHRASE_FD, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_passphrase_fd");
#endif /* WITH_SSL_SUPPORT */
        break;
      case TAG_SSL_PASSPHRASE_FILE:
#ifdef WITH_SSL_SUPPORT
        opt_p(&(opt.ssl_passphrase_file), optarg, &(opt.ssl_mask),
			MASK_SSL_PASSPHRASE_FILE, f);
#else /* WITH_SSL_SUPPORT */
	NO_SSL_OPT("ssl_passphrase_file");
#endif /* WITH_SSL_SUPPORT */
        break;
      default:
        VANESSA_LOGGER_DEBUG_RAW("Unknown Option");
        break;
    }
  }

  if (opt.ssl_mask & MASK_SSL_PASSPHRASE_FD &&
      opt.ssl_mask & MASK_SSL_PASSPHRASE_FILE) {
    VANESSA_LOGGER_DEBUG_RAW("Only one of ssl_passphrase_fd and "
			     "ssl_passphrase_file may be specified");
    if (f&OPT_ERR) {
      usage(-1);
    }
    else {
        poptFreeContext(context);
        return -1;
    }
  }

  if (c < -1) {
    VANESSA_LOGGER_DEBUG_UNSAFE( "%s: %s",
      poptBadOption(context, POPT_BADOPTION_NOALIAS), poptStrerror(c));
    return opt_err(f, context);
  }

  trailing_argv = poptGetArgs(context);
  if(trailing_argv && *trailing_argv) {
    while(*trailing_argv) {
      VANESSA_LOGGER_DEBUG_UNSAFE("trailing argument: %s", *trailing_argv);
      trailing_argv++;
    }
    usage(-1);
  }
  
  opt.domain_delimiter_length=strlen(opt.domain_delimiter);
  poptFreeContext(context);

  return(0);
}


#define BIN_OPT_STR(_opt) ((_opt)?"on":"off")

static const char *opt_str(const char *opt)
{
	if (!opt)
		return "";
	return opt;
}
#define OPT_STR(_opt) opt_str(_opt)


/**********************************************************************
 * log_options_str_free
 * Free return value of log_options_str()
 * pre: a: array of strings to free
 * post: a is freed
 * return: none
 **********************************************************************/

void log_options_str_free(char **a)
{
	int i;

	for (i = 0; i < 4; i++)
		if (a[i])
			free(a[i]);

	free(a);
}


/**********************************************************************
 * log_options_str
 * Log options to a null-terminated array of strings
 * pre: global opt is set
 * post: options are logged to a
 *       Caller must free strings in a using log_options_str_free()
 * return: 0 on success
 *         1 on error
 **********************************************************************/

static char *log_options_head_str(void)
{
	char *out = NULL;
	char *protocol=NULL;

	out = malloc(MAX_LINE_LENGTH);
	if (!out) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		return NULL;
	}

	if((protocol=protocol_list(protocol, NULL, opt.protocol))==NULL) {
		VANESSA_LOGGER_DEBUG("protocol_list");
	}

	snprintf(out, MAX_LINE_LENGTH - 1,
		 "Starting %s version=%s protocol=%s",
		 PACKAGE,
		 VERSION,
		 protocol
	);
	if (protocol!=NULL) {
		free(protocol);
		protocol=NULL;
	}
	return out;
}

#define LOG_OPTIONS_ADD_STR(str, dest, start) \
{ \
  if(dest!=start) \
    *dest++=','; \
  strcpy(dest, str); \
  dest+=strlen(dest); \
}

#define LOG_OPTIONS_BUILD_USERNAME_MODIFIER(_opt, _str) \
{ \
  char *current; \
 \
  current=_str; \
  if(_opt&STATE_GET_SERVER && _opt&STATE_LOCAL_AUTH && \
      _opt&STATE_REMOTE_LOGIN) { \
    LOG_OPTIONS_ADD_STR("all", current, _str); \
  } \
  else { \
    if(_opt&STATE_GET_SERVER){ \
      LOG_OPTIONS_ADD_STR("servername_lookup", current, _str); \
    } \
    if(_opt&STATE_LOCAL_AUTH){ \
      LOG_OPTIONS_ADD_STR("local_authentication", current, _str); \
    } \
    if(_opt&STATE_REMOTE_LOGIN){ \
      LOG_OPTIONS_ADD_STR("remote_login", current, _str); \
    } \
    if(current==_str){ \
      *current='\0'; \
    } \
  } \
}

static char *log_options_non_ssl_str(void)
{
  int status = -1;
  char *out = NULL;
  char *protocol=NULL;
  char *outgoing_server=NULL;
  char *bind_address=NULL;
  char *query_key=NULL;
  char add_domain[40];
  char lower_case[40];
  char strip_domain[40];

  out = malloc(MAX_LINE_LENGTH);
  if (!out) {
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    return NULL;
  }

  if((protocol=protocol_list(protocol, NULL, opt.protocol))==NULL){
    VANESSA_LOGGER_DEBUG("protocol_list");
    goto err;
  }

  if(opt.outgoing_server!=NULL){
    if((outgoing_server=vanessa_dynamic_array_display(
      opt.outgoing_server,
      OPT_SERVER_DELIMITER
    ))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_dynamic_array_display");
      goto err;
    }
  }

  if(opt.bind_address!=NULL){
    if((bind_address=vanessa_dynamic_array_display(
      opt.bind_address,
      OPT_SERVER_DELIMITER
    ))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_dynamic_array_display");
      goto err;
    }
  }

  if(opt.query_key!=NULL){
    if((query_key=vanessa_dynamic_array_display(
      opt.query_key,
      OPT_SERVER_DELIMITER
    ))==NULL){
      VANESSA_LOGGER_DEBUG("vanessa_dynamic_array_display");
      goto err;
    }
  }

  LOG_OPTIONS_BUILD_USERNAME_MODIFIER(opt.add_domain, add_domain);
  if (*add_domain) {
    snprintf(add_domain + strlen(add_domain), 
		    39 - strlen(add_domain), ",%d", 
		    opt.add_domain_strip_depth);
    add_domain[39] = '\0';
  }
  LOG_OPTIONS_BUILD_USERNAME_MODIFIER(opt.lower_case, lower_case);
  LOG_OPTIONS_BUILD_USERNAME_MODIFIER(opt.strip_domain, strip_domain);

  snprintf(
    out,
    MAX_LINE_LENGTH - 1,
    "add_domain=\"%s\", "
#ifdef WITH_PAM_SUPPORT
    "authenticate_in=%s, "
#endif /* WITH_PAM_SUPPORT */
    "authenticate_timeout=%d, "
    "bind_address=\"%s\", "
    "client_server_specification=%s, "
    "config_file=\"%s\", "
    "connection_limit=%d, "
    "connection_logging=%s, "
    "connect_relog=%d, "
    "debug=%s, "
    "domain_delimiter=\"%s\", "
    "explicit_domain=\"%s\", "
    "group=\"%s\", "
    "imap_capability=\"%s\", "
    "inetd_mode=%s, "
    "listen_port=\"%s\", "
    "log_facility=\"%s\", "
    "log_passwd=\"%s\", "
    "login_disabled=%s, "
    "lower_case=\"%s\", "
    "managesieve_capability=\"%s\", "
    "map_library=\"%s\", "
    "map_library_opt=\"%s\", "
    "no_bind_banner=%s, "
    "no_daemon=%s, "
    "no_lookup=%s, "
    "tcp_keepalive=%s, "
    "nodename=\"%s\", "
    "ok_line=\"%s\", "
    "outgoing_port=\"%s\", "
    "outgoing_server=\"%s\", "
    "pid_file=\"%s\", "
    "pop_capability=\"%s\", "
    "protocol=\"%s\", "
    "server_resp_line=%s, "
    "strip_domain=\"%s\", "
    "timeout=%d, "
    "username=\"%s\", "
    "username_from_database=%s, "
    "query_key=\"%s\", " 
    "quiet=%s "
    "(mask=0x%08x %08x)",
    OPT_STR(add_domain),
#ifdef WITH_PAM_SUPPORT
    BIN_OPT_STR(opt.authenticate_in),
#endif /* WITH_PAM_SUPPORT */
    opt.authenticate_timeout,
    OPT_STR(bind_address),
    BIN_OPT_STR(opt.client_server_specification),
    OPT_STR(opt.config_file),
    opt.connection_limit,
    BIN_OPT_STR(opt.connection_logging),
    opt.connect_relog,
    BIN_OPT_STR(opt.debug),
    OPT_STR(opt.domain_delimiter),
    OPT_STR(opt.explicit_domain),
    OPT_STR(opt.group),
    OPT_STR(opt.imap_capability),
    BIN_OPT_STR(opt.inetd_mode),
    OPT_STR(opt.listen_port),
    OPT_STR(opt.log_facility),
    OPT_STR(log_passwd_to_str(opt.log_passwd)),
    BIN_OPT_STR(opt.login_disabled),
    OPT_STR(lower_case),
    OPT_STR(opt.managesieve_capability),
    OPT_STR(opt.map_library),
    OPT_STR(opt.map_library_opt),
    BIN_OPT_STR(opt.no_bind_banner),
    BIN_OPT_STR(opt.no_daemon),
    BIN_OPT_STR(opt.no_lookup),
    BIN_OPT_STR(opt.tcp_keepalive),
    OPT_STR(system_uname->nodename),
    OPT_STR(opt.ok_line),
    OPT_STR(opt.outgoing_port),
    OPT_STR(outgoing_server),
    OPT_STR(opt.pid_file),
    OPT_STR(opt.pop_capability),
    protocol,
    BIN_OPT_STR(opt.server_resp_line),
    strip_domain,
    opt.timeout,
    OPT_STR(opt.username),
    BIN_OPT_STR(opt.username_from_database),
    OPT_STR(query_key),
    BIN_OPT_STR(opt.quiet),
    opt.mask, opt.mask2
  );
  out[MAX_LINE_LENGTH - 1] = '\0';

  status = 0;
err:
  if (status) {
    str_free(out);
    out = NULL;
  }
  str_free(protocol);
  str_free(outgoing_server);
  str_free(bind_address);
  str_free(query_key);
  return out;
}

#ifdef WITH_SSL_SUPPORT
static char *log_options_ssl_str(void)
{
	char ssl_mode[40];
	char *ssl_mode_p = NULL;
	char *out = NULL;

	out = malloc(MAX_LINE_LENGTH);
	if (!out) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		return NULL;
	}

	switch (opt.ssl_mode) {
	case SSL_MODE_EMPTY:
		*ssl_mode = '\0';
		break;
	case SSL_MODE_NONE:
		strcpy(ssl_mode, "none");
		break;
	default:
		ssl_mode_p=ssl_mode;
		if (opt.ssl_mode & SSL_MODE_SSL_LISTEN &&
		    opt.ssl_mode & SSL_MODE_SSL_OUTGOING)
			LOG_OPTIONS_ADD_STR("ssl_all", ssl_mode_p, ssl_mode)
		else if (opt.ssl_mode & SSL_MODE_TLS_LISTEN &&
			 opt.ssl_mode & SSL_MODE_TLS_OUTGOING)
			LOG_OPTIONS_ADD_STR("tls_all", ssl_mode_p, ssl_mode)
		else {
			if (opt.ssl_mode & SSL_MODE_SSL_LISTEN)
				LOG_OPTIONS_ADD_STR("ssl_listen", ssl_mode_p,
						    ssl_mode)
			if (opt.ssl_mode & SSL_MODE_SSL_OUTGOING)
				LOG_OPTIONS_ADD_STR("ssl_outgoing", ssl_mode_p,
						    ssl_mode)
			if (opt.ssl_mode & SSL_MODE_TLS_LISTEN)
				LOG_OPTIONS_ADD_STR("tls_listen", ssl_mode_p,
						    ssl_mode)
			if (opt.ssl_mode & SSL_MODE_TLS_OUTGOING)
				LOG_OPTIONS_ADD_STR("tls_outgoing", ssl_mode_p,
						    ssl_mode)
			if (ssl_mode_p == ssl_mode)
				*ssl_mode_p='\0';
		}
		break;
	}
	if ((opt.ssl_mode & SSL_MODE_TLS_OUTGOING_FORCE) &&
	    (opt.ssl_mode & SSL_MODE_TLS_LISTEN_FORCE)) {
		LOG_OPTIONS_ADD_STR("tls_all_force", ssl_mode_p, ssl_mode)
	}
	else {
		if (opt.ssl_mode&SSL_MODE_TLS_OUTGOING_FORCE)
			LOG_OPTIONS_ADD_STR("tls_outgoing_force", ssl_mode_p,
					    ssl_mode)
		if (opt.ssl_mode&SSL_MODE_TLS_LISTEN_FORCE)
			LOG_OPTIONS_ADD_STR("tls_listen_force", ssl_mode_p,
					    ssl_mode)
	}

	snprintf(out, MAX_LINE_LENGTH - 1,
		 "ssl_mode=\"%s\", "
		 "ssl_ca_file=\"%s\", "
		 "ssl_ca_path=\"%s\", "
		 "ssl_ca_accept_self_signed=\"%s\", "
		 "ssl_cert_file=\"%s\", "
		 "ssl_cert_accept_expired=\"%s\", "
		 "ssl_cert_not_yet_valid=\"%s\", "
		 "ssl_cert_self_signed=\"%s\", "
		 "ssl_cert_verify_depth=%d, "
		 "ssl_key_file=\"%s\", "
		 "ssl_listen_ciphers=\"%s\", "
		 "ssl_outgoing_ciphers=\"%s\", "
		 "ssl_no_cert_verify=\"%s\", "
		 "ssl_no_client_cert_verify=\"%s\", "
		 "ssl_no_cn_verify=\"%s\" "
		 "ssl_passphrase_fd=%d, "
		 "ssl_passphrase_file=\"%s\", "
		 "(ssl_mask=0x%08x) ",
		 ssl_mode,
		 OPT_STR(opt.ssl_ca_file),
		 OPT_STR(opt.ssl_ca_path),
		 BIN_OPT_STR(opt.ssl_ca_accept_self_signed),
		 OPT_STR(opt.ssl_cert_file),
		 BIN_OPT_STR(opt.ssl_cert_accept_expired),
		 BIN_OPT_STR(opt.ssl_cert_accept_not_yet_valid),
		 BIN_OPT_STR(opt.ssl_cert_accept_self_signed),
		 opt.ssl_cert_verify_depth,
		 OPT_STR(opt.ssl_key_file),
		 OPT_STR(opt.ssl_listen_ciphers),
		 OPT_STR(opt.ssl_outgoing_ciphers),
		 BIN_OPT_STR(opt.ssl_no_cert_verify),
		 BIN_OPT_STR(opt.ssl_no_client_cert_verify),
		 BIN_OPT_STR(opt.ssl_no_cn_verify),
		 opt.ssl_passphrase_fd,
		 opt.ssl_passphrase_file,
		 opt.ssl_mask);
	out[MAX_LINE_LENGTH - 1] = '\0';

	return out;
}
#endif /* WITH_SSL_SUPPORT */

char **log_options_str(void)
{
	char **a;

	a = calloc(4, sizeof(char *));
	if (!a) {
		VANESSA_LOGGER_DEBUG_ERRNO("calloc");
		return NULL;
	}

	a[0] = log_options_head_str();
	if (!a[0])
		goto err;
	a[1] = log_options_non_ssl_str();
	if (!a[1])
		goto err;
#ifdef WITH_SSL_SUPPORT
	a[2] = log_options_ssl_str();
	if (!a[2])
		goto err;
#endif /* WITH_SSL_SUPPORT */

	return a;
err:
	log_options_str_free(a);
	return NULL;
}


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

int log_options(void)
{
	char **a, **p;

	a = log_options_str();
	if (!a) {
		VANESSA_LOGGER_DEBUG("log_options_str");
		return -1;
	}

	if (opt.debug) {
		for (p = a; *p; p++) {
			if (strlen(*p)) {
				VANESSA_LOGGER_INFO(*p);
			}
		}
	} else {
		VANESSA_LOGGER_INFO(*a);
	}

	log_options_str_free(a);

	return 0;
}


/**********************************************************************
 * usage
 * Display usage information
 * pre: exit_status: status to exit programme with
 * post: Usage information is displayed stdout if exit_status=0, stderr
 *       otherwise.
 *       Programme exits with exit status.
 * return: does not return
 **********************************************************************/

void usage(int exit_status){
  FILE *stream;
  char *available_protocols=NULL;
  char *default_protocol_str=NULL;

  if(exit_status < 0) {
	  sleep(USAGE_ERROR_SLEEP);
  }

  stream=(exit_status)?stderr:stdout;

  if((available_protocols=protocol_list(
    available_protocols, 
    ", ", 
    PROTOCOL_ALL
  ))==NULL){
    VANESSA_LOGGER_DEBUG("protocol_list 1");
    available_protocols="*error*";
  }

  if((default_protocol_str=protocol_list(
    default_protocol_str, 
    NULL,
    PROTOCOL_DEFAULT
  ))==NULL){
    VANESSA_LOGGER_DEBUG("protocol_list 2");
    default_protocol_str="*error*";
  }

  fprintf(
    stream, 
    "perdition version %s Copyright Horms\n"
    "\n"
    "perdition is a mail retrieval proxy daemon\n"
    "\n"
    "Usage: perdition [options]\n"
    "\n"
    "Options:\n"
    " -A|--add_domain STATE[,STATE...][,STRIP_DEPTH]:\n"
    "    Appends a domain to the USER based on the IP address connected to\n"
    "    in given state(s). (default \"\")\n"
#ifdef WITH_PAM_SUPPORT
    " -a|--authenticate_in:\n"
    "    User is authenticated by perdition before connection to real-server.\n"
#endif /* WITH_PAM_SUPPORT */
    " --authenticate_timeout:\n"
    "    Timeout used during authentication phase.\n"
    "    Zero for infinite timeout. (default %d)\n"
    " -B|--no_bind_banner:\n"
    "    Use uname to generate banner of even if bind_address is in effect.\n"
    " -b|--bind_address SERVER[,SERVER...]:\n"
    "    Bind to these addresses and ports.\n"
    "    (default \"%s\")\n"
    " -C|--connection_logging:\n"
    "    Log all communication received from end-users or real servers or\n"
    "    sent from perdition.\n"
    "    Note: debug must be in effect for this option to take effect.\n"
    " --connect_relog SECONDS:\n"
    "    How often to relog the connection.\n"
    "    Zero for no relogging. (default %d)\n"
    " -c|--client_server_specification:\n"
    "    Allow end-user to specify the real-server.\n"
    " -D|--domain_delimiter STRING:\n"
    "    Delimiter between username and domain. (default \"%s\")\n"
    " -d|--debug:\n"
    "    Turn on verbose debugging.\n"
    " -e|--explicit_domain STRING:\n"
    "    With -A, use STRING as the default domain rather than deriving\n"
    "    from the IP address connected to.\n"
    " -F|--log_facility FACILITY:\n"
    "    Facility to log to. (default \"%s\")\n"
    " -f|--config_file FILENAME:\n"
    "    Name of config file to read.\n"
    "    (default is invocation independent)\n"
    " -g|--group group:\n"
    "     Group to run as. (default \"%s\")\n"
    " -h|--help:\n"
    "    Display this message.\n"
    " -I|--capability STRING:\n"
    "    Deprecated in favour of --pop_capability, --managesieve_capability\n"
    "    and --imap_capability.\n"
    " --imap_capability STRING:\n"
    "    Capabilities for imap4 and imap4s.\n"
    "    (default \"%s\")\n"
    " -i|--inetd_mode:\n"
    "    Run in inetd mode.\n"
    " -L|--connection_limit number LIMIT:\n"
    "    Maximum number of simultaneous connections to accept.\n"
    "    Zero for no limit. (default %d)\n"
    " -l|--listen_port PORT_NUMBER|PORT_NAME:\n"
    "    Port to listen on. (default \"%s\")\n"
    " --login_disabled:\n"
    "    Do not allow users to log in.\n"
    " --log_passwd STATE:\n"
    "    Log the users password, otherwise just report it as \"XXXXXX\".\n"
    "    (default \"%s\")\n"
    " --lower_case STATE[,STATE...]:\n"
    "    Convert usernames to lower case according the the locale in given\n"
    "    state(s). (default \"\")\n"
    " --managesieve_capability STRING:\n"
    "    Capabilities for managesieve.\n"
    "    (default \"%s\")\n"
    " -M|--map_library FILENAME:\n"
    "    Library to open that provides functions to look up the server for a\n"
    "    user.\n"
    "    (default \"%s\")\n"
    " -m|--map_library_opt STRING:\n"
    "    String option for the map_library. (default \"%s\")\n"
    " --no_daemon:\n"
    "    Do not detach from terminal.\n"
    " -n|--no_lookup:\n"
    "    Disable host and port lookup.\n"
    " -O|--ok_line STRING:\n"
    "    Use STRING as the OK line to send to the client.\n"
    "    Overridden by server_resp_line.\n"
    "    (default \"%s\")\n"
    " -o|--server_resp_line:\n"
    "    Use back-end server's authentication response, instead of \n"
    "    generating one.\n"
    " --pop_capability STRING:\n"
    "    Capabilities for pop3 and pop3s.\n"
    "    (default \"%s\")\n"
    " -P|--protocol PROTOCOL:\n"
    "    Protocol to use.\n"
    "    (default \"%s\")\n"
    "    available protocols: \"%s\"\n"
    " -p|--outgoing_port PORT_NAME|PORT_NUMBER:\n"
    "    Default real-server port. (default \"%s\")\n"
    " -s|--outgoing_server SERVER[,SERVER...]:\n"
    "    Default server(s). (default \"%s\")\n"
    " --pid_file FILENAME\n"
    "    Path for pidfile. Must be a full path starting with a '/'.\n"
    "    Empty for no pid file. Not used in inetd mode.\n"
    "    (default \"%s/ARGV[0]\")\n"
    " -S|--strip_domain STATE[,STATE...]:\n"
    "    Allow domain portion of username to be striped in given state(s).\n"
    "    (default \"\")\n"
    " -t|--timeout SECONDS:\n"
    "    Idle timeout for post-authentication phase.\n"
    "    Zero for infinite timeout. (default %d)\n"
    " -u|--username USERNAME:\n"
    "    User to run as. (default \"%s\")\n"
    " -U|--username_from_database:\n"
    "    Substitute username from popmap lookup.\n"
    " -q|--quiet:\n"
    "    Only log errors. Overridden by debug\n"
    " --query_key FORMAT[,FORMAT...]:\n"
    "    Specify a list of query strings to search for in the popmap.\n"
    "    (default \"%s\")\n"
#ifdef WITH_SSL_SUPPORT
    "\n"
    "SSL/TLS Specific Options:\n"
    " --ssl_mode MODE[,MODE ...]:\n"
    "    Use SSL and or TLS for the listening and/or outgoing connections.\n"
    "    (default \"%s\")\n"
    " --ssl_ca_chain_file:\n"
    "    Chain file containing Certificate Authorities to use when \n"
    "    verifying certificates. Overrides ssl_ca_file and ssl_ca_path\n"
    "    (default \"%s\")\n"
    "    (recommended location \"%s\")\n"
    " --ssl_ca_file FILENAME:\n"
    "    File containing Certificate Authorities to use when verifying\n"
    "    certificates. When building the Certificate Authorities chain,\n"
    "    ssl_ca_file is used first, if set, and then ssl_ca_path, if set.\n"
    "    (default \"%s\")\n"
    "    (recommended location \"%s\")\n"
    " --ssl_ca_path DIRECTORYNAME:\n"
    "    Directory containing Certificate Authorities files to use when\n"
    "    verifying certificates. When building the Certificate Authorities\n"
    "    chain, ssl_ca_file is used first, if set, and then ssl_ca_path,\n"
    "    if set.\n"
    "    (default \"%s\")\n"
    " --ssl_ca_accept_self_signed:\n"
    "    Accept self-signed certificates.\n"
    " --ssl_cert_file FILENAME:\n"
    "    Certificate chain to use when listening for SSL or TLS connections.\n"
    "    (default \"%s\")\n"
    " --ssl_cert_accept_self_signed:\n"
    "    Accept self-signed certificates.\n"
    " --ssl_cert_accept_expired:\n"
    "    Accept expired certificates. This includes server certificates\n"
    "    and certificate authority certificates.\n"
    " --ssl_cert_accept_not_yet_valid:\n"
    "    Accept certificates that are not yet valid. This includes server\n"
    "    certificates and certificate authority certificates.\n"
    " --ssl_cert_verify_depth DEPTH:\n"
    "    Chain Depth to recurse to when verifying certificates.\n"
    "    (default %d)\n"
    " --ssl_key_file FILENAME:\n"
    "    Public key to use when listening for SSL or TLS connections.\n"
    "    (default \"%s\")\n"
    " --ssl_listen_ciphers STRING:\n"
    "    Cipher list when listening for SSL or TLS connections.\n"
    "    If empty (\"\") then openssl's default will be used.\n"
    "    (default \"%s\")\n"
    " --ssl_outgoing_ciphers STRING:\n"
    "    Cipher list when making outgoing SSL or TLS connections.\n"
    "    If empty (\"\") then openssl's default will be used.\n"
    "    (default \"%s\")\n"
    " --ssl_no_cert_verify:\n"
    "    Don't cryptographically verify certificates.\n"
    " --ssl_no_client_cert_verify:\n"
    "    Don't cryptographically verify the end-user's certificate.\n"
    " --ssl_no_cn_verify:\n"
    "    Don't verify the real-server's common name with the name used\n"
    "    to connect to the server.\n"
    " --ssl_passphrase_fd N:\n"
    "    File descriptor from with the passphrase for the certificate\n"
    "    is read.\n"
    "    (default %d)\n"
    " --ssl_passphrase_file FILENAME:\n"
    "    File from with the passphrase for the certificate is read.\n"
    "    (default \"%s\")\n"
#endif /* WITH_SSL_SUPPORT */
    "\n"
    " Notes: Default value for binary flags is off.\n"
    "        If a string argument is empty (\"\") then the option will not\n"
    "        be used unless noted otherwise.\n"
    "        See the perdition(8) man page for more details.\n",
    VERSION,
    DEFAULT_AUTHENTICATE_TIMEOUT,
    OPT_STR(DEFAULT_BIND_ADDRESS),
    DEFAULT_CONNECT_RELOG,
    OPT_STR(DEFAULT_DOMAIN_DELIMITER),
    OPT_STR(DEFAULT_LOG_FACILITY),
    OPT_STR(DEFAULT_GROUP),
    OPT_STR(DEFAULT_IMAP_CAPABILITY),
    DEFAULT_CONNECTION_LIMIT,
    OPT_STR(PERDITION_PROTOCOL_DEPENDANT),
    OPT_STR(log_passwd_to_str(DEFAILT_LOG_PASSWD)),
    OPT_STR(DEFAULT_MANAGESIEVE_CAPABILITY),
    OPT_STR(DEFAULT_MAP_LIB),
    OPT_STR(DEFAULT_MAP_LIB_OPT),
    OPT_STR(DEFAULT_OK_LINE),
    OPT_STR(DEFAULT_IMAP_CAPABILITY),
    OPT_STR(default_protocol_str),
    OPT_STR(available_protocols),
    OPT_STR(PERDITION_PROTOCOL_DEPENDANT),
    OPT_STR(DEFAULT_OUTGOING_SERVER),
    OPT_STR(PERDITION_PID_DIR),
    DEFAULT_TIMEOUT,
    OPT_STR(DEFAULT_USERNAME),
    OPT_STR(DEFAULT_QUERY_KEY)
#ifdef WITH_SSL_SUPPORT
    ,
    OPT_STR(NULL),
    OPT_STR(DEFAULT_SSL_CA_CHAIN_FILE),
    OPT_STR(RECOMMENDED_SSL_CA_CHAIN_FILE),
    OPT_STR(DEFAULT_SSL_CA_FILE),
    OPT_STR(RECOMMENDED_SSL_CA_FILE),
    OPT_STR(DEFAULT_SSL_CA_PATH),
    OPT_STR(DEFAULT_SSL_CERT_FILE),
    DEFAULT_SSL_CERT_VERIFY_DEPTH,
    OPT_STR(DEFAULT_SSL_KEY_FILE),
    OPT_STR(DEFAULT_SSL_LISTEN_CIPHERS),
    OPT_STR(DEFAULT_SSL_OUTGOING_CIPHERS),
    DEFAULT_SSL_PASSPHRASE_FD,
    OPT_STR(DEFAULT_SSL_PASSPHRASE_FILE)
#endif /* WITH_SSL_SUPPORT */
  );

  fflush(stream);
  vanessa_socket_daemon_exit_cleanly(exit_status);
}


#define ADD_TO_SERVER_PORT \
do {                                                                        \
	usp = NULL;                                                         \
	user_server_port_str_assign(&usp, string);                          \
	if(!vanessa_dynamic_array_add_element(a, usp)){                     \
		return(NULL);                                               \
	}                                                                   \
} while(0)


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
){
  vanessa_dynamic_array_t *a;
  char *sub_string;
  user_server_port_t *usp;

  if(string==NULL){ return(NULL); }
  if((a=vanessa_dynamic_array_create(
	0, 
	DESTROY_SP,
	DUPLICATE_SP,
	DISPLAY_SP,
	LENGTH_SP
    ))==NULL){
    return(NULL);
  }
  while((sub_string=strchr(string, delimiter))!=NULL){
    *sub_string='\0';
    ADD_TO_SERVER_PORT;
    string=sub_string+1;
  }
  if(*string!='\0'){
    ADD_TO_SERVER_PORT;
  }
  return(a);
}
