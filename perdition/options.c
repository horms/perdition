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
  char *basename;
  char *optarg_copy;
  poptContext context;

  static struct poptOption options[] =
  {
    {"authenticate_in",             'a', POPT_ARG_NONE,   NULL, 'a'},
    {"no_bind_banner",              'B', POPT_ARG_NONE,   NULL, 'B'},
    {"bind_address",                'b', POPT_ARG_STRING, NULL, 'b'},
    {"connection_logging",          'C', POPT_ARG_NONE,   NULL, 'C'},
    {"client_server_specification", 'c', POPT_ARG_STRING, NULL, 'c'},
    {"domain_delimiter",            'D', POPT_ARG_STRING, NULL, 'D'},
    {"debug",                       'd', POPT_ARG_NONE,   NULL, 'd'},
    {"log_facility",                'F', POPT_ARG_STRING, NULL, 'F'},
    {"config_file",                 'f', POPT_ARG_STRING, NULL, 'f'},
    {"group",                       'g', POPT_ARG_STRING, NULL, 'g'},
    {"help",                        'h', POPT_ARG_NONE,   NULL, 'h'},
    {"inetd_mode",                  'i', POPT_ARG_NONE,   NULL, 'i'},
    {"jain",                        'j', POPT_ARG_NONE,   NULL, 'j'},
    {"jane",                        'j', POPT_ARG_NONE,   NULL, 'j'},
    {"jayne",                       'j', POPT_ARG_NONE,   NULL, 'j'},
    {"connection_limit",            'L', POPT_ARG_STRING, NULL, 'L'},
    {"listen_port",                 'l', POPT_ARG_STRING, NULL, 'l'},
    {"map_library",                 'M', POPT_ARG_STRING, NULL, 'M'},
    {"map_library_opt",             'm', POPT_ARG_STRING, NULL, 'm'},
    {"no_lookup",                   'n', POPT_ARG_NONE,   NULL, 'n'},
    {"server_ok_line",              'o', POPT_ARG_NONE,   NULL, 'o'},
    {"protocol",                    'P', POPT_ARG_STRING, NULL, 'P'},
    {"outgoing_port",               'p', POPT_ARG_STRING, NULL, 'p'},
    {"strip_domain",                'S', POPT_ARG_STRING, NULL, 'S'},
    {"outgoing_server",             's', POPT_ARG_STRING, NULL, 's'},
    {"timeout",                     't', POPT_ARG_STRING, NULL, 't'},
    {"username",                    'u', POPT_ARG_STRING, NULL, 't'},
    {"quiet",                       'q', POPT_ARG_NONE,   NULL, 'q'},
    {NULL,                           0,   0,               NULL, 0  }
  };

  basename=basename_str(argv[0]);

  if(argc==0 || argv==NULL) return(0);

  /* i is used as a dummy variable */
  if(f&OPT_SET_DEFAULT){
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
    opt_i(opt.server_ok_line,  DEFAULT_SERVER_OK_LINE,      i, 0, OPT_NOT_SET);
    opt_i(opt.strip_domain,    DEFAULT_STRIP_DOMAIN,        i, 0, OPT_NOT_SET);
    opt_i(opt.timeout,         DEFAULT_TIMEOUT,             i, 0, OPT_NOT_SET);
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
  }

  if(f&OPT_CLEAR_MASK) opt.mask=(flag_t)0;

  context= poptGetContext("perdition", argc, (const char **)argv, options, 0);

  while ((c=poptGetNextOpt(context)) >= 0){
    optarg=(char *)poptGetOptArg(context);
    switch (c){
      case 'a':
#ifdef WITH_PAM_SUPPORT
        opt_i(opt.authenticate_in,1,opt.mask,MASK_AUTHENTICATE_IN,f); \
        break;
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
        if(f&OPT_ERR){ 
	  printf( "Jain, Oath\n"); 
	}
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
        opt_i(opt.strip_domain,1,opt.mask,MASK_STRIP_DOMAIN,f);
        break;
      case 's':
        if(options_set_mask(&(opt.mask), f, MASK_OUTGOING_SERVER)){
          if(!(f&OPT_NOT_SET) && opt.outgoing_server!=NULL) {
            vanessa_dynamic_array_destroy(opt.outgoing_server);
          }
	  if((optarg_copy=strdup(optarg)) == NULL){
            PERDITION_LOG(LOG_DEBUG, "options: strdup: %s", strerror(errno));
            if(f&OPT_ERR) daemon_exit_cleanly(-1);
	  }
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
      case 'q':
        opt_i(opt.quiet,1,opt.mask,MASK_QUIET,f);
        break;
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
    "connection_logging=%d, "
    "debug=%d, "
    "domain_delimiter=\"%s\", "
    "group=\"%s\", "
    "inetd_mode=%d, "
    "listen_port=\"%s\", "
    "log_facility=\"%s\", "
    "map_library=\"%s\", "
    "map_library_opt=\"%s\", "
    "no_bind_banner=%d, "
    "no_lookup=%d, "
    "nodename=\"%s\", "
    "outgoing_port=\"%s\", "
    "outgoing_server=\"%s\", "
    "prototol=\"%s\", "
    "server_ok_line=%d, "
    "strip_domain=%d, "
    "timeout=%d, "
    "username=\"%s\", "
    "quiet=%d " 
    "(mask=0x%x)\n",
#ifdef WITH_PAM_SUPPORT
    opt.authenticate_in,
#endif /* WITH_PAM_SUPPORT */
    str_null_safe(opt.bind_address),
    opt.client_server_specification,
    opt.config_file,
    opt.connection_limit,
    opt.connection_logging,
    opt.debug,
    str_null_safe(opt.domain_delimiter),
    str_null_safe(opt.group),
    opt.inetd_mode,
    str_null_safe(opt.listen_port),
    str_null_safe(opt.log_facility),
    str_null_safe(opt.map_library),
    str_null_safe(opt.map_library_opt),
    opt.no_bind_banner,
    opt.no_lookup,
    str_null_safe(system_uname->nodename),
    str_null_safe(opt.outgoing_port),
    str_null_safe(outgoing_server),
    protocol,
    opt.server_ok_line,
    opt.strip_domain,
    opt.timeout,
    str_null_safe(opt.username),
    opt.quiet,
    opt.mask
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
    "\n"
    "Options:\n"
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
    " -b|--bind_address:\n"
    "    Bind to interfaces with this address. In non-inetd mode, connections\n"
    "    will only be accepted on interfaces with this address. If NULL\n"
    "    connections will be accepted from all interfaces. In inetd and\n"
    "    non-inetd mode the source address of connections to real servers\n"
    "    will be this address, if NULL then the operating system will select\n"
    "    a source address. The address may be an IP address or a hostname.\n"
    "    (default \"%s\")\n"
    " -C|--connection_logging:\n"
    "    Log interaction during authentication phase\n"
    "    Note: -d|--debug must be specified for this option to take effect.\n"
    " -c|--client_server_specification:\n"
    "    Allow USER of the form user<delimiter>server[:port] to specify the\n"
    "    server and port for a user. Note: over-rides -s|--strip_domain.\n"
    " -D|--domain_delimiter:\n"
    "    Delimiter used for -c|--client_server_specification and\n"
    "    -s|--strip_domain options. Multicharacter delimiters are permitted.\n"
    "    (default \"%s\")\n"
    " -d|--debug:\n"
    "    Turn on verbose debuging.\n"
    " -F|--logging_facility:\n"
    "    Syslog facility to log to. If the faclilty has a leading '/' then it\n"
    "    will be treated as a file to log to. (default \"%s\")\n"
    "    Note: If an error occurs before options are read it may be loged\n"
    "    to syslog faclilty mail\n"
    " -f|--config_file:\n"
    "    Name of config file to read. If set to \"\" no config file will be\n"
    "    used. Command line options override options set in config file.\n"
    "    (default \"%s\")\n"
    " -g|--group:\n"
    "     Group to run as. (default \"%s\")\n"
    " -h|--help:\n"
    "    Display this message\n"
    " -i|--inetd_mode:\n"
    "    Run in inetd mode\n"
    " -L|--connection_limit:\n"
    "    Maximum number of connections to accept simultaneously. A value of\n"
    "    zero sets no limit on the number of simultaneous connections.\n"
    "    (default %d)\n"
    " -l|--listen_port:\n"
    "    Port to listen on. (default \"%s\")\n"
    " -M|--map_library:\n"
    "    Library to open that provides functions to look up the server for a\n"
    "    user. A null library mean no library will be accessed and hence, no\n"
    "    lookup will take place.\n"
    "    (default \"%s\")\n"
    " -m|--map_library_opt:\n"
    "    String option to pass to databse access function provided by the\n"
    "    library specified by the -M|--map_library option. The treatment of\n"
    "    this string is up to the library, in the case of perditiondb_gdbm\n"
    "    the gdbm map to access is set. (default \"%s\")\n"
    " -n|--no_lookup:\n"
    "    Disable host and port lookup Implies -B|--no_bind_banner\n"
    " -o|--server_ok_line:\n"
    "    If authentication with the back-end server is successful then send\n"
    "    the servers +OK line to the client, instead of generting one.\n"
    " -P|--protocol:\n"
    "    Protocol to use.\n"
    "    (default \"%s\")\n"
    "    available protocols: \"%s\"\n"
    " -p|--outgoing_port:\n"
    "    Define a port to use if a port is not defined for a user in popmap,\n"
    "    or a default server if it is used. (default \"%s\")\n"
    " -s|--outgoing_server:\n"
    "    Define a server to use if a user is not in the popmap. Format is\n"
    "    servername[:port]. Multipleservers can be delimited by a ','. If\n"
    "    multiple servers are specified then they are used in a round robin.\n"
    "    (default \"%s\")\n"
    " -S|--strip_domain:\n"
    "    Allow USER of the from user<delimiter>domain where <delimiter>domain\n"
    "    will be striped off Note: over-ridden by\n"
    "    -c|--client_server_specification.\n"
    " -t|--timeout:\n"
    "    Idle timeout in seconds. Value of zero sets infinite timeout.\n"
    "    (default %d)\n"
    " -u|--username:\n"
    "    Username to run as. (default \"%s\")\n"
    " -q|--quiet:\n"
    "    Only log errors. Overriden by -d|--debug\n"
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
