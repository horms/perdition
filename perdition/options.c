/**********************************************************************
 * options.c                                             September 1999
 * Horms                                             horms@vergenet.net
 *
 * Read in command line options
 * Code based on man getopt(3), later translated to popt
 *
 * perdition
 * Mail retreival proxy server
 * Copyright (C) 1999  Horms
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


/**********************************************************************
 * opt_help
 * Display help, only if we are in ERR mode
 **********************************************************************/

#define opt_help \
  if(f&OPT_ERR && !(f&OPT_FILE)){ usage(0); } \
  break;


/**********************************************************************
 * opt_jain
 * Display Jain message, only if we are in ERR mode
 **********************************************************************/

#define opt_jain \
  if(f&OPT_ERR){ printf( "Jain, Oath\n"); } \
  break;


/**********************************************************************
 * opt_map_library
 * Set map_library
 **********************************************************************/

#define opt_map_library \
  opt_p(opt.map_library,optarg,opt.mask,MASK_MAP_LIB,f); \
  break;


/**********************************************************************
 * opt_map_library_opt
 * Set map_library_opt
 **********************************************************************/

#define opt_map_library_opt \
  opt_p(opt.map_library_opt,optarg,opt.mask,MASK_MAP_LIB_OPT,f); \
  break;


/**********************************************************************
 * opt_inetd_mode
 * Turn inetd mode on
 **********************************************************************/

#define opt_inetd_mode \
  opt_i(opt.inetd_mode,1,opt.mask,MASK_INETD_MODE,f); \
  break;


/**********************************************************************
 * opt_debug
 * Turn debug on
 **********************************************************************/

#define opt_debug \
  opt_i(opt.debug,1,opt.mask,MASK_DEBUG,f); \
  break;


/**********************************************************************
 * opt_quiet
 * Turn quiet mode
 **********************************************************************/

#define opt_quiet \
  opt_i(opt.quiet,1,opt.mask,MASK_QUIET,f); \
  break;


/**********************************************************************
 * opt_no_lookup
 * Turn quiet mode
 **********************************************************************/

#define opt_no_lookup \
  opt_i(opt.no_lookup,1,opt.mask,MASK_NO_LOOKUP,f); \
  break;


/**********************************************************************
 * opt_config_file
 * Set configuration file, unless this is being effected
 * from a configuration file
 **********************************************************************/

#define opt_config_file \
  if(!(f&OPT_FILE)){  \
    opt_p(opt.config_file,optarg,opt.mask,MASK_CONFIG_FILE,f);  \
  } \
  break;


/**********************************************************************
 * opt_domain_delimiter
 * Set domain delimiter
 **********************************************************************/

#define opt_domain_delimiter \
  opt_p(opt.domain_delimiter,optarg,opt.mask,MASK_DOMAIN_DELIMITER,f); \
  break;


/**********************************************************************
 * opt_outgoing_server
 * Set outgoing server
 **********************************************************************/
   
#define opt_outgoing_server \
  if(options_set_mask(&(opt.mask), f, MASK_OUTGOING_SERVER)){ \
    if(!(f&OPT_NOT_SET) && opt.outgoing_server!=NULL) { \
      vanessa_dynamic_array_destroy(opt.outgoing_server); \
    } \
    opt.outgoing_server=split_str_server_port( \
      strdup(optarg),  \
      OPT_SERVER_DELIMITER \
    ); \
  } \
  break;


/**********************************************************************
 * opt_outgoing_port
 * Set outgoing port
 **********************************************************************/

#define opt_outgoing_port \
  opt_p(opt.outgoing_port,optarg,opt.mask,MASK_OUTGOING_PORT,f); \
  break;


/**********************************************************************
 * opt_client_server_specification
 * Turn client_server_specification on
 **********************************************************************/
   
#define opt_client_server_specification \
  opt_i( \
    opt.client_server_specification, \
    1, \
    opt.mask, \
    MASK_CLIENT_SERVER_SPECIFICATION, \
    f \
  ); \
  break;


/**********************************************************************
 * opt_strip_domain
 * Turn strip domain on
 **********************************************************************/
   
#define opt_strip_domain \
  opt_i(opt.strip_domain,1,opt.mask,MASK_STRIP_DOMAIN,f); \
  break;


#ifdef WITH_PAM_SUPPORT
/**********************************************************************
 * opt_authenticate_in
 * Turn local authentication on
 **********************************************************************/
        
#define opt_authenticate_in \
  opt_i(opt.authenticate_in,1,opt.mask,MASK_AUTHENTICATE_IN,f); \
  break;
#endif /* WITH_PAM_SUPPORT */


/**********************************************************************
 * opt_server_ok_line
 * Turn server ok line on
 **********************************************************************/
        
#define opt_server_ok_line \
  opt_i(opt.server_ok_line,1,opt.mask,MASK_SERVER_OK_LINE,f); \
  break;


/**********************************************************************
 * opt_listen_port
 * Set listen port
 **********************************************************************/
 
#define opt_listen_port \
  opt_p(opt.listen_port,optarg,opt.mask,MASK_LISTEN_PORT,f); \
  break;


/**********************************************************************
 * opt_protocol
 * Set protocol
 **********************************************************************/

#define opt_protocol \
  if((index=protocol_index(optarg))<0){ \
    PERDITION_LOG(LOG_DEBUG, "options: invalid protocol: %s", optarg); \
    if(f&OPT_ERR) usage(-1); \
  } \
  else { \
    opt_i(opt.protocol,index,opt.mask,MASK_PROTOCOL,f); \
  } \
  break;


/**********************************************************************
 * opt_username
 * Set username
 **********************************************************************/

#define opt_username \
  opt_p(opt.username,optarg,opt.mask,MASK_USERNAME,f); \
  break;


/**********************************************************************
 * opt_group
 * Set group
 **********************************************************************/

#define opt_group \
  opt_p(opt.group,optarg,opt.mask,MASK_GROUP,f); \
  break;


/**********************************************************************
 * opt_bind_address
 * Set bind_address
 **********************************************************************/

#define opt_bind_address \
  opt_p(opt.bind_address,optarg,opt.mask,MASK_BIND_ADDRESS,f); \
  break;


/**********************************************************************
 * opt_timeout
 * Set timeout
 **********************************************************************/

#define opt_timeout \
  if(!vanessa_socket_str_is_digigt(optarg) && f&OPT_ERR){ usage(-1); } \
  opt_i(opt.timeout,atoi(optarg),opt.mask,MASK_TIMEOUT,f); \
  break;


/**********************************************************************
 * opt_connection_limit
 * Set connection_limit
 **********************************************************************/

#define opt_connection_limit \
  if(!vanessa_socket_str_is_digigt(optarg) && f&OPT_ERR){ usage(-1); } \
  opt_i(opt.connection_limit,atoi(optarg),opt.mask,MASK_CONNECTION_LIMIT,f); \
  break;


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
  char *optarg;
  poptContext context;


  static struct poptOption options[] =
  {
    {"authenticate_in",             'a', POPT_ARG_NONE,   NULL, 'a'},
    {"bind_address",                'b', POPT_ARG_STRING, NULL, 'b'},
    {"config_file",                 'f', POPT_ARG_STRING, NULL, 'f'},
    {"connection_limit",            'L', POPT_ARG_STRING, NULL, 'L'},
    {"client_server_specification", 'c', POPT_ARG_STRING, NULL, 'c'},
    {"debug",                       'd', POPT_ARG_NONE,   NULL, 'd'},
    {"domain_delimiter",            'D', POPT_ARG_STRING, NULL, 'D'},
    {"group",                       'g', POPT_ARG_STRING, NULL, 'g'},
    {"help",                        'h', POPT_ARG_NONE,   NULL, 'h'},
    {"inetd_mode",                  'i', POPT_ARG_NONE,   NULL, 'i'},
    {"jain",                        'j', POPT_ARG_NONE,   NULL, 'j'},
    {"jane",                        'j', POPT_ARG_NONE,   NULL, 'j'},
    {"jayne",                       'j', POPT_ARG_NONE,   NULL, 'j'},
    {"map_library",                 'M', POPT_ARG_STRING, NULL, 'M'},
    {"map_library_opt",             'm', POPT_ARG_STRING, NULL, 'm'},
    {"no_lookup",                   'n', POPT_ARG_NONE,   NULL, 'n'},
    {"outgoing_server",             's', POPT_ARG_STRING, NULL, 's'},
    {"outgoing_port",               'p', POPT_ARG_STRING, NULL, 'p'},
    {"protocol",                    'P', POPT_ARG_STRING, NULL, 'P'},
    {"listen_port",                 'l', POPT_ARG_STRING, NULL, 'l'},
    {"server_ok_line",              'o', POPT_ARG_STRING, NULL, 'o'},
    {"strip_domain",                'S', POPT_ARG_STRING, NULL, 'S'},
    {"timeout",                     't', POPT_ARG_STRING, NULL, 't'},
    {"username",                    'u', POPT_ARG_STRING, NULL, 't'},
    {"quiet",                       'q', POPT_ARG_NONE,   NULL, 'q'},
    {NULL,                           0,   0,               NULL, 0  }
  };

  if(argc==0 || argv==NULL) return(0);

  /* i is used as a dummy variable */
  if(f&OPT_SET_DEFAULT){
#ifdef WITH_PAM_SUPPORT
    opt_i(opt.authenticate_in, DEFAULT_AUTHENTICATE_IN,     i, 0, OPT_NOT_SET);
#endif /* WITH_PAM_SUPPORT */
    opt_i(opt.client_server_specification, DEFAULT_CLIENT_SERVER_SPECIFICATION,
                                                            i, 0, OPT_NOT_SET);
    opt_i(opt.connection_limit,DEFAULT_CONNECTION_LIMIT,    i, 0, OPT_NOT_SET);
    opt_i(opt.debug,           DEFAULT_DEBUG,               i, 0, OPT_NOT_SET);
    opt_i(opt.inetd_mode,      DEFAULT_INETD_MODE,          i, 0, OPT_NOT_SET);
    opt_i(opt.protocol,        DEFAULT_PROTOCOL,            i, 0, OPT_NOT_SET);
    opt_i(opt.no_lookup,       DEFAULT_NO_LOOKUP,           i, 0, OPT_NOT_SET);
    opt_i(opt.server_ok_line,  DEFAULT_SERVER_OK_LINE,      i, 0, OPT_NOT_SET);
    opt_i(opt.strip_domain,    DEFAULT_STRIP_DOMAIN,        i, 0, OPT_NOT_SET);
    opt_i(opt.timeout,         DEFAULT_TIMEOUT,             i, 0, OPT_NOT_SET);
    opt_i(opt.quiet,           DEFAULT_QUIET,               i, 0, OPT_NOT_SET);
    opt_p(opt.bind_address,    DEFAULT_BIND_ADDRESS,        i, 0, OPT_NOT_SET);
    opt_p(opt.config_file,     DEFAULT_CONFIG_FILE,         i, 0, OPT_NOT_SET);
    opt_p(opt.domain_delimiter,DEFAULT_DOMAIN_DELIMITER,    i, 0, OPT_NOT_SET);
    opt_p(opt.group,           DEFAULT_GROUP,               i, 0, OPT_NOT_SET);
    opt_p(opt.listen_port,     PERDITION_PROTOCOL_DEPENDANT,i, 0, OPT_NOT_SET);
    opt_p(opt.map_library,     DEFAULT_MAP_LIB,             i, 0, OPT_NOT_SET);
    opt_p(opt.map_library_opt, DEFAULT_MAP_LIB_OPT,         i, 0, OPT_NOT_SET);
    opt_p(opt.outgoing_port,   PERDITION_PROTOCOL_DEPENDANT,i, 0, OPT_NOT_SET);
    opt_da(opt.outgoing_server,DEFAULT_OUTGOING_SERVER,     i, 0, OPT_NOT_SET);
    opt_p(opt.username,        DEFAULT_USERNAME,            i, 0, OPT_NOT_SET);
  }

  if(f&OPT_CLEAR_MASK) opt.mask=(flag_t)0;

  context= poptGetContext("perdition", argc, argv, options, 0);

  while ((c=poptGetNextOpt(context)) >= 0){
    optarg=poptGetOptArg(context);
    switch (c){
      case 'a':
#ifdef WITH_PAM_SUPPORT
  	opt_authenticate_in;
#else
      if(f&OPT_ERR){
        fprintf(
	  stderr, 
	  "-a|--authenticate in only supported when compiled against libpam\n"
        );
        sleep(1);
        usage(-1);
      }
      else{
        PERDITION_LOG(
	  LOG_DEBUG,  
	  "-a|--authenticate in only supported when compiled against libpam"
        );
        poptFreeContext(context);
        return(-1);
      }
#endif /* WITH_PAM_SUPPORT */
      case 'b':
  	opt_bind_address;
      case 'c':
  	opt_client_server_specification;
      case 'D':
        opt_domain_delimiter;
      case 'd':
        opt_debug;
      case 'f':
        opt_config_file;
      case 'g':
        opt_group;
      case 'h':
        opt_help;
      case 'i':
        opt_inetd_mode;
      case 'j':
        opt_jain;
      case 'L':
        opt_connection_limit;
      case 'l':
        opt_listen_port;
      case 'M':
        opt_map_library;
      case 'm':
        opt_map_library_opt;
      case 'n':
        opt_no_lookup;
      case 'o':
        opt_server_ok_line;
      case 'P':
        opt_protocol;
      case 'p':
        opt_outgoing_port;
      case 'S':
        opt_strip_domain;
      case 's':
        opt_outgoing_server;
      case 't':
        opt_timeout;
      case 'u':
  	opt_username;
      case 'q':
        opt_quiet;
    }
  }

  if (c < -1) {
    char tmp_buf[BUFFER_SIZE];
    snprintf(
      tmp_buf, 
      BUFFER_SIZE, 
      "options: %s: %s\n",
      poptBadOption(context, POPT_BADOPTION_NOALIAS),
      poptStrerror(c)
    );

    if(f&OPT_ERR){
      fprintf(stderr, "%s", tmp_buf);
      sleep(1);
      usage(-1);
    }
    else{
      PERDITION_LOG(LOG_DEBUG, tmp_buf);
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


/**********************************************************************
 * log_options
 * Log options
 **********************************************************************/

int log_options(void){
  char *protocol=NULL;
  char *outgoing_server=NULL;

  extern options_t opt;
  extern struct utsname *system_uname;
  extern vanessa_logger_t *perdition_vl;

  if((protocol=protocol_list(protocol, NULL, opt.protocol))==NULL){
    PERDITION_LOG(LOG_DEBUG, "log_options: protocol_list");
    return(-1);
  }

  if(opt.outgoing_server!=NULL){
    if((outgoing_server=vanessa_dynamic_array_display(
      opt.outgoing_server,
      OPT_SERVER_DELIMITER
    ))==NULL){
      PERDITION_LOG(LOG_DEBUG, "log_options: vanessa_dynamic_array_display");
      free(protocol);
      return(-1);
    }
  }

  vanessa_logger_log(
    perdition_vl,
    LOG_INFO, 
#ifdef WITH_PAM_SUPPORT
    "authenticate_in=%d, "
#endif /* WITH_PAM_SUPPORT */
    "bind_address=\"%s\", "
    "client_server_specification=%d, "
    "config_file=\"%s\", "
    "connection_limit=%d, "
    "debug=%d, "
    "domain_delimiter=\"%s\", "
    "group=\"%s\", "
    "inetd_mode=%d, "
    "listen_port=\"%s\", "
    "map_library=\"%s\", "
    "map_library_opt=\"%s\", "
    "no_lookup=%d, "
    "nodename=\"%s\", "
    "outgoing_port=\"%s\", "
    "outgoing_server=\"%s\", "
    "prototol=\"%s\", "
    "server_ok_line=%d, "
    "strip_domain=%d, "
    "timeout=%d, "
    "username=\"%s\", "
    "quiet=%d\n",
#ifdef WITH_PAM_SUPPORT
    opt.authenticate_in,
#endif /* WITH_PAM_SUPPORT */
    str_null_safe(opt.bind_address),
    opt.client_server_specification,
    opt.config_file,
    opt.connection_limit,
    opt.debug,
    str_null_safe(opt.domain_delimiter),
    str_null_safe(opt.group),
    opt.inetd_mode,
    str_null_safe(opt.listen_port),
    str_null_safe(opt.map_library),
    str_null_safe(opt.map_library_opt),
    opt.no_lookup,
    str_null_safe(system_uname->nodename),
    str_null_safe(opt.outgoing_port),
    str_null_safe(outgoing_server),
    protocol,
    opt.server_ok_line,
    opt.strip_domain,
    opt.timeout,
    str_null_safe(opt.username),
    opt.quiet
  );

  if(protocol!=NULL){ free(protocol); }
  if(outgoing_server!=NULL){ free(outgoing_server); }
  return(0);
}


/**********************************************************************
 * usage
 * Display usage information
 * Printed to stdout if exit_status=0, stderr otherwise
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
    PERDITION_LOG(LOG_DEBUG, "usage: protocol_list 1");
    available_protocols="*error*";
  }

  if((default_protocol_str=protocol_list(
    default_protocol_str, 
    NULL,
    PROTOCOL_DEFAULT
  ))==NULL){
    PERDITION_LOG(LOG_DEBUG, "usage: protocol_list 2");
    default_protocol_str="*error*";
  }

  fprintf(
    stream, 
    "perdition version %s Copyright Horms\n"
    "\n"
    "perdition is an mail retrieval proxy daemon\n"
    "\n"
    "Usage: perdition [options]\n"
    "  options:\n"
#ifdef WITH_PAM_SUPPORT
    "     -a|--authenticate_in:\n"
    "                      User is authenticated by perdition before\n"
    "                      connection to backend server is made.\n"
#endif /* WITH_PAM_SUPPORT */
    "     -b|--bind_address:\n"
    "                      Bind to interfaces with this address.\n"
    "                      The address may be an IP address or\n"
    "                      a hostname.\n"
    "                      If NULL then bind to all interfaces.\n"
    "                      (default \"%s\")\n"
    "     -c|--client_server_specification:\n"
    "                      Allow USER of the form ser<delimiter>server[:port]\n"
    "                      to specify the server and port for a user.\n"
    "                      Note: over-rides -s|--strip_domain.\n"
    "     -D|--domain_delimiter:\n"
    "                      Delimiter used for\n"
    "                      -c|--client_server_specification and\n"
    "                      -s|--strip_domain options. Multicharacter\n"
    "                      delimiters are permitted.\n"
    "                      (default \"%s\")\n"
    "     -d|--debug:      Turn on verbose debuging.\n"
    "     -f|--config_file:\n"
    "                      Name of config file to read. If set to \"\" no\n"
    "                      config file will be used. Command line options\n"
    "                      override options set in config file.\n"
    "                      (default \"%s\")\n"
    "     -g|--group:      Group to run as.\n"
    "                      (default \"%s\")\n"
    "     -h|--help:       Display this message\n"
    "     -i|--inetd_mode: Run in inetd mode\n"
    "     -L|--connection_limit:\n"
    "                      Maximum number of connections to accept\n"
    "                      simultaneously. A value of zero sets\n"
    "                      no limit on the number of simultaneous\n"
    "                      connections.\n"
    "                      (default %d)\n"
    "     -l|--listen_port:\n"
    "                      Port to listen on.\n"
    "                      (default \"%s\")\n"
    "     -M|--map_library:\n"
    "                      Library to open that provides functions to look\n"
    "                      up the server for a user. A null library mean\n"
    "                      no library will be accessed and hence, no lookup\n"
    "                      will take place.\n"
    "                      (default \"%s\")\n"
    "     -m|--map_library_opt:\n"
    "                      String option to pass to databse access function\n"
    "                      provided by the library specified by the\n"
    "                      -M|--map_library option. The treatment of this\n"
    "                      string is up to the library, in the case of\n"
    "                      perditiondb_gdbm the gdbm map to access is set.\n"
    "                      (default \"%s\")\n"
    "     -n|--no_lookup:  Disable host and port lookup\n"
    "     -o|--server_ok_line:\n"
    "                      If authentication with the back-end server is\n"
    "                      successful then send the servers +OK line to\n"
    "                      the client, instead of generting one\n"
    "     -P|--protocol:   Protocol to use.\n"
    "                      (default \"%s\")\n"
    "                      available protocols: \"%s\"\n"
    "     -p|--outgoing_port:\n"
    "                      Define a port to use if a port is not defined for\n"
    "                      a user in popmap, or a default server if it is\n"
    "                      used.\n"
    "                      (default \"%s\")\n"
    "     -s|--outgoing_server:\n"
    "                      Define a server to use if a user is not in the\n"
    "                      popmap. Format is servername[:port]. Multiple\n"
    "                      servers can be delimited by a ','. If multiple\n"
    "                      servers are specified then they are used in a\n"
    "                      round robin.\n"
    "                      (default \"%s\")\n"
    "     -S|--strip_domain:\n"
    "                      Allow USER of the from user<delimiter>domain where\n"
    "                      <delimiter>domain will be striped off\n"
    "                      Note: over-ridden by\n"
    "                      -c|--client_server_specification\n"
    "     -t|--timeout:    Idle timeout in seconds. Value of zero sets\n"
    "                      infinite timeout.\n"
    "                      (default %d)\n"
    "     -u|--username:   Username to run as\n"
    "                      (default \"%s\")\n"
    "     -q|--quiet  :    Only log errors. Overriden by -d|--debug\n"
    "\n"
    "     Note: default value for binary flags is off\n",
    VERSION,
    str_null_safe(DEFAULT_BIND_ADDRESS),
    str_null_safe(DEFAULT_DOMAIN_DELIMITER),
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
  );

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
