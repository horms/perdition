/**********************************************************************
 * options.c                                             September 1999
 * Horms                                             horms@vergenet.net
 *
 * Read in command line options
 * Code based on man getopt(3), later translated to popt
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

#include "options.h"

options_t opt;


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

#define opt_p(opt, value, mask, mask_entry, flag) \
  if(options_set_mask(&(mask), mask_entry, flag)){ \
    if(!((flag)&OPT_NOT_SET) && opt!=NULL){ free(opt); } \
    opt=(value==NULL)?NULL:strdup(value); \
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

#define opt_i(opt, value, mask, mask_entry, flag) \
  if(options_set_mask(&(mask), mask_entry, flag)){ \
    opt=value; \
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
 *       value is addigned to into opt.ss. Any existing value of opt is freed
 *       The mask may also be altered as per options_set_mask()
 *       Else no change.
 ***********************************************************************/

#define opt_da(opt, value, mask, mask_entry, flag) \
  if(options_set_mask(&(mask), mask_entry, flag)){ \
    if(!((flag)&OPT_NOT_SET) && opt!=NULL){ \
      vanessa_dynamic_array_destroy(opt); \
    } \
    opt=value; \
  } \


#define opt_i_or(opt, value, mask, mask_entry, flag) \
  opt_i(opt, opt|value, mask, mask_entry, flag)

#define OPT_MODIFY_USERNAME(opt, mask, mask_entry, flag, id_str) \
  if(strcasecmp(optarg_copy, "all")==0){ \
    opt_i_or(opt, STATE_ALL, mask, mask_entry, flag); \
  } \
  else if( \
    strcasecmp(optarg_copy, "servername_lookup")==0 || \
    strcasecmp(optarg_copy, "server_lookup")==0 \
  ){ \
    opt_i_or(opt, STATE_GET_SERVER, mask, mask_entry, flag); \
  } \
  else if( \
    strcasecmp(optarg_copy, "local_authentication")==0 || \
    strcasecmp(optarg_copy, "local_auth")==0 \
  ){ \
    opt_i_or(opt, STATE_LOCAL_AUTH, mask, mask_entry, flag); \
  } \
  else if(strcasecmp(optarg_copy, "remote_login")==0){ \
    opt_i_or(opt, STATE_REMOTE_LOGIN, mask, mask_entry, flag); \
  } \
  else { \
    PERDITION_ERR_UNSAFE("unknown state for %s: %s", id_str, optarg_copy); \
    if(f&OPT_ERR) { \
      sleep(1); \
      usage(-1); \
    } \
  }

#define OPT_STRIP_DOMAIN \
  OPT_MODIFY_USERNAME(opt.strip_domain, opt.mask, MASK_STRIP_DOMAIN, f, \
    "strip_domain");

#define OPT_ADD_DOMAIN \
  OPT_MODIFY_USERNAME(opt.add_domain, opt.mask, MASK_ADD_DOMAIN, f, \
    "add_domain");

#define OPT_LOWER_CASE \
  OPT_MODIFY_USERNAME(opt.lower_case, opt.mask, MASK_LOWER_CASE, f, \
    "lower_case");

#define OPTARG_DUP \
  if(optarg==NULL){ \
    PERDITION_DEBUG("OPTARG_DUP: optarg is NULL"); \
    if(f&OPT_ERR) daemon_exit_cleanly(-1); \
  } \
  if((optarg_copy=strdup(optarg)) == NULL){ \
    PERDITION_DEBUG_ERRNO("strdup"); \
    if(f&OPT_ERR) daemon_exit_cleanly(-1); \
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
    else if(strcasecmp(optarg_copy, "tls_all")==0){ \
       new=SSL_MODE_TLS_ALL; \
    } \
    else { \
     PERDITION_ERR_UNSAFE("unknown ssl_mode: %s", optarg_copy); \
      if(f&OPT_ERR) { \
        sleep(1); \
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
      PERDITION_DEBUG("invalid ssl_mode combination"); \
      if(f&OPT_ERR) daemon_exit_cleanly(-1); \
    } \
    /* TLS support hasn't been implemented yet */ \
    /* if(new!=SSL_MODE_NONE && new&SSL_TLS_MASK){ */ \
    /*  PERDITION_DEBUG("TLS not implemented"); */ \
    /*  if(f&OPT_ERR) daemon_exit_cleanly(-1); */ \
    /*} */ \
    opt_i_or(opt.ssl_mode, new, opt.ssl_mask, MASK_SSL_MODE, f); \
  }
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

  static struct poptOption options[] =
  {
    {"add_domain",                  'A',  POPT_ARG_STRING, NULL,  'A'},
    {"authenticate_in",             'a',  POPT_ARG_NONE,   NULL, 'a'},
    {"no_bind_banner",              'B',  POPT_ARG_NONE,   NULL, 'B'},
    {"bind_address",                'b',  POPT_ARG_STRING, NULL, 'b'},
    {"connection_logging",          'C',  POPT_ARG_NONE,   NULL, 'C'},
    {"client_server_specification", 'c',  POPT_ARG_NONE,   NULL, 'c'},
    {"domain_delimiter",            'D',  POPT_ARG_STRING, NULL, 'D'},
    {"debug",                       'd',  POPT_ARG_NONE,   NULL, 'd'},
    {"log_facility",                'F',  POPT_ARG_STRING, NULL, 'F'},
    {"config_file",                 'f',  POPT_ARG_STRING, NULL, 'f'},
    {"group",                       'g',  POPT_ARG_STRING, NULL, 'g'},
    {"help",                        'h',  POPT_ARG_NONE,   NULL, 'h'},
    {"inetd_mode",                  'i',  POPT_ARG_NONE,   NULL, 'i'},
    {"jain",                        'j',  POPT_ARG_NONE,   NULL, 'j'},
    {"jane",                        'j',  POPT_ARG_NONE,   NULL, 'j'},
    {"jayne",                       'j',  POPT_ARG_NONE,   NULL, 'j'},
    {"connection_limit",            'L',  POPT_ARG_STRING, NULL, 'L'},
    {"listen_port",                 'l',  POPT_ARG_STRING, NULL, 'l'},
    {"map_library",                 'M',  POPT_ARG_STRING, NULL, 'M'},
    {"map_library_opt",             'm',  POPT_ARG_STRING, NULL, 'm'},
    {"no_lookup",                   'n',  POPT_ARG_NONE,   NULL, 'n'},
    {"server_ok_line",              'o',  POPT_ARG_NONE,   NULL, 'o'},
    {"protocol",                    'P',  POPT_ARG_STRING, NULL, 'P'},
    {"outgoing_port",               'p',  POPT_ARG_STRING, NULL, 'p'},
    {"strip_domain",                'S',  POPT_ARG_STRING, NULL, 'S'},
    {"outgoing_server",             's',  POPT_ARG_STRING, NULL, 's'},
    {"timeout",                     't',  POPT_ARG_STRING, NULL, 't'},
    {"username",                    'u',  POPT_ARG_STRING, NULL, 'u'},
    {"username_from_database",      'U',  POPT_ARG_NONE,   NULL, 'U'},
    {"quiet",                       'q',  POPT_ARG_NONE,   NULL, 'q'},
    {"lower_case",                  'x',  POPT_ARG_STRING, NULL, 'X'},
    {"ssl_mode",                    '\0', POPT_ARG_STRING, NULL, 
      TAG_SSL_MODE },
    {"ssl_cert_file",               '\0', POPT_ARG_STRING, NULL, 
      TAG_SSL_CERT_FILE },
    {"ssl_key_file",                '\0', POPT_ARG_STRING, NULL, 
      TAG_SSL_KEY_FILE },
    {NULL,                           0,   0,               NULL, 0 }
  };

  basename=str_basename(argv[0]);

  if(argc==0 || argv==NULL) return(0);

  /* i is used as a dummy variable */
  if(f&OPT_SET_DEFAULT){
    opt_i(opt.add_domain,      DEFAULT_ADD_DOMAIN,          i, 0, OPT_NOT_SET);
#ifdef WITH_PAM_SUPPORT
    opt_i(opt.authenticate_in, DEFAULT_AUTHENTICATE_IN,     i, 0, OPT_NOT_SET);
#endif /* WITH_PAM_SUPPORT */
    opt_i(opt.no_bind_banner,  DEFAULT_NO_BIND_BANNER,      i, 0, OPT_NOT_SET);
    opt_i(opt.client_server_specification, DEFAULT_CLIENT_SERVER_SPECIFICATION,
                                                            i, 0, OPT_NOT_SET);
    opt_i(opt.connection_limit,DEFAULT_CONNECTION_LIMIT,    i, 0, OPT_NOT_SET);
    opt_i(opt.connection_logging,DEFAULT_CONNECTION_LOGGING,i, 0, OPT_NOT_SET);
    opt_i(opt.debug,           DEFAULT_DEBUG,               i, 0, OPT_NOT_SET);
    opt_i(opt.inetd_mode,      DEFAULT_INETD_MODE,          i, 0, OPT_NOT_SET);
    if(!(f&OPT_FILE) && !strcmp("perdition.imap4", basename)){
      opt_i(opt.protocol,      PROTOCOL_IMAP4,              i, 0, OPT_NOT_SET);
    }
    else if(!(f&OPT_FILE) && !strcmp("perdition.pop3", basename)){
      opt_i(opt.protocol,      PROTOCOL_POP3,               i, 0, OPT_NOT_SET);
    }
    else {
      opt_i(opt.protocol,      DEFAULT_PROTOCOL,            i, 0, OPT_NOT_SET);
    }
    opt_i(opt.no_lookup,       DEFAULT_NO_LOOKUP,           i, 0, OPT_NOT_SET);
    opt_i(opt.add_domain,      DEFAULT_LOWER_CASE,          i, 0, OPT_NOT_SET);
    opt_i(opt.server_ok_line,  DEFAULT_SERVER_OK_LINE,      i, 0, OPT_NOT_SET);
    opt_i(opt.strip_domain,    DEFAULT_STRIP_DOMAIN,        i, 0, OPT_NOT_SET);
    opt_i(opt.timeout,         DEFAULT_TIMEOUT,             i, 0, OPT_NOT_SET);
    opt_i(opt.username_from_database, DEFAULT_USERNAME_FROM_DATABASE, 
                                                            i, 0, OPT_NOT_SET);
    opt_i(opt.quiet,           DEFAULT_QUIET,               i, 0, OPT_NOT_SET);
    opt_p(opt.bind_address,    DEFAULT_BIND_ADDRESS,        i, 0, OPT_NOT_SET);
    opt_p(opt.log_facility,    DEFAULT_LOG_FACILITY,        i, 0, OPT_NOT_SET);
    opt_p(opt.config_file,     DEFAULT_CONFIG_FILE,         i, 0, OPT_NOT_SET);
    opt_p(opt.domain_delimiter,DEFAULT_DOMAIN_DELIMITER,    i, 0, OPT_NOT_SET);
    opt_p(opt.group,           DEFAULT_GROUP,               i, 0, OPT_NOT_SET);
    opt_p(opt.listen_port,     PERDITION_PROTOCOL_DEPENDANT,i, 0, OPT_NOT_SET);
    opt_p(opt.map_library,     DEFAULT_MAP_LIB,             i, 0, OPT_NOT_SET);
    opt_p(opt.map_library_opt, DEFAULT_MAP_LIB_OPT,         i, 0, OPT_NOT_SET);
    opt_p(opt.outgoing_port,   PERDITION_PROTOCOL_DEPENDANT,i, 0, OPT_NOT_SET);
    opt_da(opt.outgoing_server,DEFAULT_OUTGOING_SERVER,     i, 0, OPT_NOT_SET);
    opt_p(opt.username,        DEFAULT_USERNAME,            i, 0, OPT_NOT_SET);
#ifdef WITH_SSL_SUPPORT
    opt_i(opt.ssl_mode,        DEFAULT_SSL_MODE,            i, 0, OPT_NOT_SET);
    opt_p(opt.ssl_key_file,    DEFAULT_SSL_KEY_FILE,        i, 0, OPT_NOT_SET);
    opt_p(opt.ssl_cert_file,   DEFAULT_SSL_CERT_FILE,       i, 0, OPT_NOT_SET);
#endif /* WITH_SSL_SUPPORT */
  }

  if(f&OPT_CLEAR_MASK){
    opt.mask=(flag_t)0;
#ifdef WITH_SSL_SUPPORT
    opt.ssl_mask=(flag_t)0;
#endif /* WITH_SSL_SUPPORT */
  }

  context= poptGetContext("perdition", argc, (const char **)argv, options, 0);

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
        opt_i(opt.authenticate_in,1,opt.mask,MASK_AUTHENTICATE_IN,f); \
        break;
#else
      PERDITION_DEBUG(
	"-a|--authenticate is only supported when compiled against libpam");
      if(f&OPT_ERR){
        sleep(1);
        usage(-1);
      }
      else{
        poptFreeContext(context);
        return(-1);
      }
#endif /* WITH_PAM_SUPPORT */
      case 'B':
        opt_i(opt.no_bind_banner,1,opt.mask,MASK_NO_BIND_BANNER,f);
        break;
      case 'b':
        opt_p(opt.bind_address,optarg,opt.mask,MASK_BIND_ADDRESS,f);
        break;
      case 'C':
        opt_i(opt.connection_logging,1,opt.mask,MASK_DEBUG,f);
        break;
      case 'c':
        opt_i(
          opt.client_server_specification,
          1,
          opt.mask,
          MASK_CLIENT_SERVER_SPECIFICATION,
          f
        );
        break;
      case 'D':
        opt_p(opt.domain_delimiter,optarg,opt.mask,MASK_DOMAIN_DELIMITER,f);
        break;
      case 'd':
        opt_i(opt.debug,1,opt.mask,MASK_DEBUG,f);
        break;
      case 'f':
        if(!(f&OPT_FILE)){
          opt_p(opt.config_file,optarg,opt.mask,MASK_CONFIG_FILE,f);
        }
        break;
      case 'F':
        opt_p(opt.log_facility,optarg,opt.mask,MASK_LOG_FACILITY,f);
        break;
      case 'g':
        opt_p(opt.group,optarg,opt.mask,MASK_GROUP,f);
        break;
      case 'h':
        if(f&OPT_ERR && !(f&OPT_FILE)){ 
	  usage(0); 
	}
	break;
      case 'i':
        opt_i(opt.inetd_mode,1,opt.mask,MASK_INETD_MODE,f);
        break;
      case 'j':
	PERDITION_DEBUG( "Jain, Oath\n"); 
        break;
      case 'L':
        if(!vanessa_socket_str_is_digit(optarg) && f&OPT_ERR){ 
	  usage(-1); 
	}
        opt_i(
	  opt.connection_limit,
	  atoi(optarg),
	  opt.mask,
	  MASK_CONNECTION_LIMIT,
	  f
	); \
        break;
      case 'l':
        opt_p(opt.listen_port,optarg,opt.mask,MASK_LISTEN_PORT,f);
        break;
      case 'M':
        opt_p(opt.map_library,optarg,opt.mask,MASK_MAP_LIB,f);
        break;
      case 'm':
        opt_p(opt.map_library_opt,optarg,opt.mask,MASK_MAP_LIB_OPT,f);
        break;
      case 'n':
        opt_i(opt.no_lookup,1,opt.mask,MASK_NO_LOOKUP,f);
        break;
      case 'o':
        opt_i(opt.server_ok_line,1,opt.mask,MASK_SERVER_OK_LINE,f);
        break;
      case 'P':
        if((index=protocol_index(optarg))<0){
        }
        else {
          opt_i(opt.protocol,index,opt.mask,MASK_PROTOCOL,f);
        }
        break;
      case 'p':
        opt_p(opt.outgoing_port,optarg,opt.mask,MASK_OUTGOING_PORT,f);
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
        if(!vanessa_socket_str_is_digit(optarg) && f&OPT_ERR){ 
	  usage(-1); 
	}
        opt_i(opt.timeout,atoi(optarg),opt.mask,MASK_TIMEOUT,f);
        break;
      case 'u':
        opt_p(opt.username,optarg,opt.mask,MASK_USERNAME,f);
        break;
      case 'U':
        opt_i(opt.username_from_database,1,opt.mask,
	  MASK_USERNAME_FROM_DATABASE,f);
        break;
      case 'q':
        opt_i(opt.quiet,1,opt.mask,MASK_QUIET,f);
        break;
      case 'X':
        OPTARG_DUP;
	while((end=strchr(optarg_copy, ','))!=NULL){
	  *end='\0';
	  OPT_LOWER_CASE;
	  optarg_copy=end+1;
	}
	OPT_LOWER_CASE;
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
        PERDITION_DEBUG(
	  "--ssl_mode is only supported when ssl support is compiled in");
        if(f&OPT_ERR){
          sleep(1);
          usage(-1);
        }
        else{
          poptFreeContext(context);
          return(-1);
        }
#endif /* WITH_SSL_SUPPORT */
      break;
      case TAG_SSL_CERT_FILE:
#ifdef WITH_SSL_SUPPORT
        opt_p(opt.ssl_cert_file,optarg,opt.ssl_mask,MASK_SSL_CERT_FILE,f);
#else /* WITH_SSL_SUPPORT */
      PERDITION_DEBUG(
	"--ssl_cert_file is only supported when ssl support is compiled in");
      if(f&OPT_ERR){
        sleep(1);
        usage(-1);
      }
      else{
        poptFreeContext(context);
        return(-1);
      }
#endif /* WITH_SSL_SUPPORT */
        break; 
      case TAG_SSL_KEY_FILE:
#ifdef WITH_SSL_SUPPORT
        opt_p(opt.ssl_key_file,optarg,opt.ssl_mask,MASK_SSL_KEY_FILE,f);
#else /* WITH_SSL_SUPPORT */
      PERDITION_DEBUG(
	"--ssl_key_file is only supported when ssl support is compiled in");
      if(f&OPT_ERR){
        sleep(1);
        usage(-1);
      }
      else{
        poptFreeContext(context);
        return(-1);
      }
#endif /* WITH_SSL_SUPPORT */
        break; 
      default:
        PERDITION_DEBUG("Unknown Option");
        exit;
    }
  }

  if (c < -1) {
    PERDITION_DEBUG_UNSAFE(
      "options: %s: %s",
      poptBadOption(context, POPT_BADOPTION_NOALIAS),
      poptStrerror(c)
    );
      
    if(f&OPT_ERR){
      sleep(1);
      usage(-1);
    }
    else{
      poptFreeContext(context);
      return(-1);
    }
  }
  
  opt.domain_delimiter_length=strlen(opt.domain_delimiter);
  poptFreeContext(context);

  return(0);
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

int options_set_mask(flag_t *mask, flag_t mask_entry, flag_t flag){
  if(flag&OPT_USE_MASK && (*mask)&mask_entry) return(0);
  if(flag&OPT_SET_MASK) (*mask)|=mask_entry;
  return(1);
}


#define BIN_OPT_STR(opt) ((opt)?"on":"off")

/**********************************************************************
 * log_options
 * Log options
 **********************************************************************/

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


int log_options(void){
  char *protocol=NULL;
  char *outgoing_server=NULL;
  char add_domain[40];
  char lower_case[40];
  char strip_domain[40];
#ifdef WITH_SSL_SUPPORT
  char ssl_mode[26];
  char *ssl_mode_p;
#endif /* WITH_SSL_SUPPORT */

  extern options_t opt;
  extern struct utsname *system_uname;
  extern vanessa_logger_t *perdition_vl;

  if((protocol=protocol_list(protocol, NULL, opt.protocol))==NULL){
    PERDITION_DEBUG("protocol_list");
    return(-1);
  }

  if(opt.outgoing_server!=NULL){
    if((outgoing_server=vanessa_dynamic_array_display(
      opt.outgoing_server,
      OPT_SERVER_DELIMITER
    ))==NULL){
      PERDITION_DEBUG("vanessa_dynamic_array_display");
      free(protocol);
      return(-1);
    }
  }

  LOG_OPTIONS_BUILD_USERNAME_MODIFIER(opt.add_domain, add_domain);
  LOG_OPTIONS_BUILD_USERNAME_MODIFIER(opt.lower_case, lower_case);
  LOG_OPTIONS_BUILD_USERNAME_MODIFIER(opt.strip_domain, strip_domain);
  
#ifdef WITH_SSL_SUPPORT
  switch(opt.ssl_mode){
    case SSL_MODE_EMPTY: 
      *ssl_mode='\0';
      break;
    case SSL_MODE_NONE:
      strcpy(ssl_mode, "none");
      break;
    default:
      ssl_mode_p=ssl_mode;
      if(opt.ssl_mode&SSL_MODE_SSL_LISTEN 
          && opt.ssl_mode&SSL_MODE_SSL_OUTGOING)
        LOG_OPTIONS_ADD_STR("ssl_all", ssl_mode_p, ssl_mode)
      else if(opt.ssl_mode&SSL_MODE_TLS_LISTEN &&
          opt.ssl_mode&SSL_MODE_TLS_OUTGOING)
        LOG_OPTIONS_ADD_STR("tls_all", ssl_mode_p, ssl_mode)
      else {
        if(opt.ssl_mode&SSL_MODE_SSL_LISTEN)
          LOG_OPTIONS_ADD_STR("ssl_listen", ssl_mode_p, ssl_mode)
        if(opt.ssl_mode&SSL_MODE_SSL_OUTGOING)
          LOG_OPTIONS_ADD_STR("ssl_outgoing", ssl_mode_p, ssl_mode)
        if(opt.ssl_mode&SSL_MODE_TLS_LISTEN)
          LOG_OPTIONS_ADD_STR("tls_listen", ssl_mode_p, ssl_mode)
        if(opt.ssl_mode&SSL_MODE_TLS_OUTGOING)
          LOG_OPTIONS_ADD_STR("tls_outgoing", ssl_mode_p, ssl_mode)
        if(ssl_mode_p==ssl_mode)
          *ssl_mode_p='\0';
      }
      break;
  }
#endif /* WITH_SSL_SUPPORT */

  vanessa_logger_log(
    perdition_vl,
    LOG_INFO, 
    "add_domain=\"%s\", "
#ifdef WITH_PAM_SUPPORT
    "authenticate_in=%s, "
#endif /* WITH_PAM_SUPPORT */
    "bind_address=\"%s\", "
    "client_server_specification=%s, "
    "config_file=\"%s\", "
    "connection_limit=%d, "
    "connection_logging=%s, "
    "debug=%s, "
    "domain_delimiter=\"%s\", "
    "group=\"%s\", "
    "inetd_mode=%s, "
    "listen_port=\"%s\", "
    "log_facility=\"%s\", "
    "lower_case=\"%s\", "
    "map_library=\"%s\", "
    "map_library_opt=\"%s\", "
    "no_bind_banner=%s, "
    "no_lookup=%s, "
    "nodename=\"%s\", "
    "outgoing_port=\"%s\", "
    "outgoing_server=\"%s\", "
    "prototol=\"%s\", "
    "server_ok_line=%s, "
    "strip_domain=\"%s\", "
    "timeout=%s, "
    "username=\"%s\", "
    "username_from_database=%s, "
    "quiet=%s, " 
#ifdef WITH_SSL_SUPPORT
    "ssl_mode=\"%s\", "
    "ssl_cert_file=\"%s\", "
    "ssl_key_file=\"%s\", "
    "(ssl_mask=0x%x) "
#endif /* WITH_SSL_SUPPORT */
    "(mask=0x%x)\n",
    str_null_safe(add_domain),
#ifdef WITH_PAM_SUPPORT
    BIN_OPT_STR(opt.authenticate_in),
#endif /* WITH_PAM_SUPPORT */
    str_null_safe(opt.bind_address),
    BIN_OPT_STR(opt.client_server_specification),
    str_null_safe(opt.config_file),
    opt.connection_limit,
    BIN_OPT_STR(opt.connection_logging),
    BIN_OPT_STR(opt.debug),
    str_null_safe(opt.domain_delimiter),
    str_null_safe(opt.group),
    BIN_OPT_STR(opt.inetd_mode),
    str_null_safe(opt.listen_port),
    str_null_safe(opt.log_facility),
    str_null_safe(lower_case),
    str_null_safe(opt.map_library),
    str_null_safe(opt.map_library_opt),
    BIN_OPT_STR(opt.no_bind_banner),
    BIN_OPT_STR(opt.no_lookup),
    str_null_safe(system_uname->nodename),
    str_null_safe(opt.outgoing_port),
    str_null_safe(outgoing_server),
    protocol,
    BIN_OPT_STR(opt.server_ok_line),
    strip_domain,
    BIN_OPT_STR(opt.timeout),
    str_null_safe(opt.username),
    BIN_OPT_STR(opt.username_from_database),
    BIN_OPT_STR(opt.quiet),
#ifdef WITH_SSL_SUPPORT
    ssl_mode,
    str_null_safe(opt.ssl_cert_file),
    str_null_safe(opt.ssl_key_file),
    opt.ssl_mask,
#endif /* WITH_SSL_SUPPORT */
    opt.mask
  );

  if(protocol!=NULL){ free(protocol); }
  if(outgoing_server!=NULL){ free(outgoing_server); }
  return(0);
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

  stream=(exit_status)?stderr:stdout;
  
  if((available_protocols=protocol_list(
    available_protocols, 
    ", ", 
    PROTOCOL_ALL
  ))==NULL){
    PERDITION_DEBUG("protocol_list 1");
    available_protocols="*error*";
  }

  if((default_protocol_str=protocol_list(
    default_protocol_str, 
    NULL,
    PROTOCOL_DEFAULT
  ))==NULL){
    PERDITION_DEBUG("protocol_list 2");
    default_protocol_str="*error*";
  }

  fprintf(
    stream, 
    "perdition version %s Copyright Horms\n"
    "\n"
    "perdition is an mail retrieval proxy daemon\n"
    "\n"
    "Usage: perdition [options]\n"
    "\n"
    "Options:\n"
    " -A|--add_domain:\n"
    "    Appends a domain to the USER based on the IP address connected to\n"
    "    in given state(s). State may be one of servername_lookup,\n"
    "    local_authentication, remote_login and all. See manpage for details\n"
    "    of states.\n"
    "    (default \"(null)\")\n"
#ifdef WITH_PAM_SUPPORT
    " -a|--authenticate_in:\n"
    "    User is authenticated by perdition before connection to backend\n"
    "    server is made.\n"
#endif /* WITH_PAM_SUPPORT */
    " -B|--no_bind_banner:\n"
    "    If -b|--bind_address is specified, then the address will be resolved\n"
    "    and the reverse-lookup of this will be used in the greeting. This\n"
    "    option disables this behaviour an reverts to using the uname to\n"
    "    derive the hostname for the greeting.\n"
    " -b|--bind_address ipaddress|hostname:\n"
    "    Bind to interfaces with this address. In non-inetd mode, connections\n"
    "    will only be accepted on interfaces with this address. If NULL\n"
    "    connections will be accepted from all interfaces. In inetd and\n"
    "    non-inetd mode the source address of connections to real servers\n"
    "    will be this address, if NULL then the operating system will select\n"
    "    a source address.\n"
    "    (default \"%s\")\n"
    " -C|--connection_logging:\n"
    "    Log interaction during authentication phase\n"
    "    Note: -d|--debug must be specified for this option to take effect.\n"
    " -c|--client_server_specification:\n"
    "    Allow USER of the form user<delimiter>server[:port] to specify the\n"
    "    server and port for a user.\n"
    " -D|--domain_delimiter string:\n"
    "    Delimiter used for -c|--client_server_specification and\n"
    "    -S|--strip_domain options. Multicharacter delimiters are permitted.\n"
    "    (default \"%s\")\n"
    " -d|--debug:\n"
    "    Turn on verbose debuging.\n"
    " -F|--log_facility facility:\n"
    "    Syslog facility to log to. If the faclilty has a leading '/' then it\n"
    "    will be treated as a file to log to. (default \"%s\")\n"
    "    Note: If an error occurs before options are read it may be logged\n"
    "    to syslog faclilty mail\n"
    " -f|--config_file filename:\n"
    "    Name of config file to read. If set to \"\" no config file will be\n"
    "    used. Command line options override options set in config file.\n"
    "    (default \"%s\")\n"
    " -g|--group group:\n"
    "     Group to run as. (default \"%s\")\n"
    " -h|--help:\n"
    "    Display this message\n"
    " -i|--inetd_mode:\n"
    "    Run in inetd mode\n"
    " -L|--connection_limit number:\n"
    "    Maximum number of connections to accept simultaneously. A value of\n"
    "    zero sets no limit on the number of simultaneous connections.\n"
    "    (default %d)\n"
    " -l|--listen_port:\n"
    "    Port to listen on. (default \"%s\")\n"
    " -M|--map_library filename:\n"
    "    Library to open that provides functions to look up the server for a\n"
    "    user. A null library mean no library will be accessed and hence, no\n"
    "    lookup will take place.\n"
    "    (default \"%s\")\n"
    " -m|--map_library_opt string:\n"
    "    String option to pass to databse access function provided by the\n"
    "    library specified by the -M|--map_library option. The treatment of\n"
    "    this string is up to the library, in the case of perditiondb_gdbm\n"
    "    the gdbm map to access is set. (default \"%s\")\n"
    " -n|--no_lookup:\n"
    "    Disable host and port lookup Implies -B|--no_bind_banner\n"
    " -o|--server_ok_line:\n"
    "    If authentication with the back-end server is successful then send\n"
    "    the servers +OK line to the client, instead of generting one.\n"
    " -P|--protocol protocol:\n"
    "    Protocol to use.\n"
    "    (default \"%s\")\n"
    "    available protocols: \"%s\"\n"
    " -p|--outgoing_port port:\n"
    "    Define a port to use if a port is not defined for a user in popmap,\n"
    "    or a default server if it is used. (default \"%s\")\n"
    " -s|--outgoing_server servername[,servername...]:\n"
    "    Define a server to use if a user is not in the popmap. Format is\n"
    "    servername[:port]. Multiple servers can be delimited by a ','. If\n"
    "    multiple servers are specified then they are used in a round robin.\n"
    "    (default \"%s\")\n"
    " -S|--strip_domain state[,state...]:\n"
    "    Allow USER of the from user<delimiter>domain where <delimiter>domain\n"
    "    will be striped off in given state(s). State may be one of\n"
    "    servername_lookup, local_authentication, remote_login and all\n"
    "    See manpage for details of states.\n"
    "    (default \"(null)\")\n"
    " -t|--timeout seconds:\n"
    "    Idle timeout. Value of zero sets infinite timeout.\n"
    "    (default %d)\n"
    " -u|--username username:\n"
    "    Username to run as. (default \"%s\")\n"
    " -U|--username_from_database:\n"
    "    If the servername in the popmap specified in the form:\n"
    "    user<delimiter>domain then use the username given by the servername.\n"
    "    If a servername is given in this form then the domain will be used\n"
    "    as the server to connect to, regarless of it the\n"
    "    -U|--username_from_database option is specified or not.\n"
    " -q|--quiet:\n"
    "    Only log errors. Overriden by -d|--debug\n"
    " -X|--lower_case state[,state...]:\n"
    "    Convert usernames to lower case according the the locale in given\n"
    "    state(s). State may be one of servername_lookup, \n"
    "    local_authentication, remote_login and all See manpage for details\n"
    "    of states.\n"
    "    (default \"(null)\")\n"
#ifdef WITH_SSL_SUPPORT
    " --ssl_mode:\n"
    "    Use SSL and or TLS for the listening and/or outgoing connections.\n"
    "    A comma delimited list of: none, ssl_incoming, ssl_outgoing,\n"
    "    ssl_all, tls_incoming, tls_outgoing, tls_all. See manpage for\n"
    "    details of these options.\n"
    "    (default \"%s\")\n"
    " --ssl_cert_file:\n"
    "    Certificate to use when listening for SSL or TLS connections.\n"
    "    (default \"%s\")\n"
    " --ssl_key_file:\n"
    "    Public key to use when listening for SSL or TLS connections.\n"
    "    (default \"%s\")\n"
#endif /* WITH_SSL_SUPPORT */
    "\n"
    " Note: default value for binary flags is off\n",
    VERSION,
    str_null_safe(DEFAULT_BIND_ADDRESS),
    str_null_safe(DEFAULT_DOMAIN_DELIMITER),
    str_null_safe(DEFAULT_LOG_FACILITY),
    str_null_safe(DEFAULT_CONFIG_FILE),
    str_null_safe(DEFAULT_GROUP),
    DEFAULT_CONNECTION_LIMIT,
    str_null_safe(PERDITION_PROTOCOL_DEPENDANT),
    str_null_safe(DEFAULT_MAP_LIB),
    str_null_safe(DEFAULT_MAP_LIB_OPT),
    str_null_safe(default_protocol_str),
    str_null_safe(available_protocols),
    str_null_safe(PERDITION_PROTOCOL_DEPENDANT),
    str_null_safe(DEFAULT_OUTGOING_SERVER),
    DEFAULT_TIMEOUT,
    str_null_safe(DEFAULT_USERNAME)
#ifdef WITH_SSL_SUPPORT
    ,
    str_null_safe(NULL),
    str_null_safe(DEFAULT_SSL_KEY_FILE),
    str_null_safe(DEFAULT_SSL_CERT_FILE)
#endif /* WITH_SSL_SUPPORT */
  );

  fflush(stream);
  daemon_exit_cleanly(exit_status);
}


#define _add_to_server_port \
  if((sp=server_port_create())==NULL){ \
    vanessa_dynamic_array_destroy(a); \
    return(NULL); \
  } \
  sp=server_port_strn_assign(sp, string, strlen(string)); \
  if(vanessa_dynamic_array_add_element(a, sp)==NULL){ \
    return(NULL); \
  }


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
  server_port_t *sp;

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
    _add_to_server_port
    string=sub_string+1;
  }
  if(*string!='\0'){
    _add_to_server_port
  }
  return(a);
}
