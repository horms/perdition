/**********************************************************************
 * perdition.c                                           September 1999
 * Horms                                             horms@vergenet.net
 *
 * Perdition, POP3 and IMAP4 proxy daemon
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

#include "perdition.h"

/*Use uname information here and there to idinify this system*/
struct utsname *system_uname;

/* Local and Peer address information is gloabal so perditiondb
 * libaries can access this information
 */
struct sockaddr_in *peername;
struct sockaddr_in *sockname;

/*
 * Logger that may be used by perdition and perditiondb libraries
 * This logger is also passed to libvanessa_adt and lib_vanessasocket
 * for them to log with
 */
vanessa_logger_t *perdition_vl;

/*
 * Used for opening dynamic server lookup library
 * Kept global so they can be used in signal handlers
 */
static int (*dbserver_get)(char *, char *, char **, size_t *);
static void *handle;

static void perdition_reread_handler(int sig);
static char *strip_username(char *username, int state);
static void strip_username_free(void);

/* Macro to clean things up when we jump around in the main loop*/
#define PERDITION_CLEAN_UP_MAIN \
  if(pw.pw_name!=NULL){ \
    free(pw.pw_name); \
      pw.pw_name=NULL; \
  } \
  if(pw.pw_passwd!=NULL){ \
    free(pw.pw_passwd); \
      pw.pw_passwd=NULL;\
  } \
  if (!round_robin_server){ \
    server_port_destroy(server_port); \
  } \
  server_port=NULL; \
  token_destroy(&tag); \
  strip_username_free();

/* Macro to set the uid and gid */
#ifdef WITH_PAM_SUPPORT 
#define PERDITION_SET_UID_AND_GID \
  if(opt.debug && geteuid() && opt.authenticate_in){ \
    PERDITION_LOG( \
      LOG_INFO,  \
      "Warning: not invoked as root, local authentication may fail" \
    ); \
  } \
  if(!geteuid() && daemon_setid(opt.username, opt.group)){ \
    PERDITION_LOG(LOG_ERR, "Fatal error setting group and userid. Exiting.");\
    daemon_exit_cleanly(-1); \
  }
#else
#define PERDITION_SET_UID_AND_GID \
  if(!geteuid() && daemon_setid(opt.username, opt.group)){ \
    PERDITION_LOG(LOG_ERR, "Fatal error setting group and userid. Exiting.");\
    daemon_exit_cleanly(-1); \
  }
#endif

/**********************************************************************
 * Muriel the main function
 **********************************************************************/

int main (int argc, char **argv){
  struct sockaddr_in from;
  struct sockaddr_in to;
  struct passwd pw;
  struct passwd pw2;
  unsigned char *server_ok_buf=NULL;
  unsigned char *buffer;
  server_port_t *server_port=NULL;
  protocol_t *protocol=NULL;
  token_t *tag=NULL;
  size_t server_ok_buf_size=0;
  char from_to_str[36];
  char from_str[17];
  char to_str[17];
  char *servername=NULL;
  char *username;
  char *port=NULL;
  int bytes_written=0;
  int bytes_read=0;
  int client_in=-1;
  int client_out=-1;
  int server=-1;
  int status;
  int round_robin_server=0;
  int rnd;

  extern struct sockaddr_in *peername;
  extern struct sockaddr_in *sockname;
  extern struct utsname *system_uname;
  extern options_t opt;

  /*Parse options*/
  options(argc, argv, OPT_FIRST_CALL);

  /*
   * Create Logger
   */
  if((perdition_vl=vanessa_logger_openlog_syslog_byname(
    DEFAULT_LOG_FACILITY,
    LOG_IDENT,
    opt.debug?LOG_DEBUG:LOG_INFO,
    LOG_CONS
  ))==NULL){
    fprintf(stderr, "main: vanessa_logger_openlog_syslog\n");
    fprintf(stderr, "Fatal error opening logger. Exiting.\n");
    daemon_exit_cleanly(-1);
  }

  /*Read congif file*/
  if(opt.config_file!=NULL){
    config_file_to_opt(opt.config_file);
  }

  /*Open the dbserver_get library, if we have a library*/
  if(
    opt.map_library!=NULL && 
    *(opt.map_library)!='\0' && 
    getserver_openlib(
      opt.map_library,
      opt.map_library_opt,
      &handle,&dbserver_get
    )<0
  ){
    fprintf(stderr,"dlopen of \"%s\" failed\n",str_null_safe(opt.map_library));
    PERDITION_LOG(
      LOG_ERR,
      "dlopen of \"%s\" failed",
      str_null_safe(opt.map_library)
    );
    usage(-1);
    daemon_exit_cleanly(-1);
  }

  /*Set signal handlers*/
  signal(SIGHUP,    (void(*)(int))perdition_reread_handler);
  signal(SIGINT,    (void(*)(int))daemon_exit_cleanly);
  signal(SIGQUIT,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGILL,    (void(*)(int))daemon_exit_cleanly);
  signal(SIGTRAP,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGIOT,    (void(*)(int))daemon_exit_cleanly);
  signal(SIGBUS,    (void(*)(int))daemon_exit_cleanly);
  signal(SIGFPE,    (void(*)(int))daemon_exit_cleanly);
  signal(SIGUSR1,   (void(*)(int))daemon_noop_handler);
  signal(SIGSEGV,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGUSR2,   (void(*)(int))daemon_noop_handler);
  signal(SIGPIPE,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGALRM,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGTERM,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGURG,    (void(*)(int))daemon_exit_cleanly);
  signal(SIGXCPU,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGXFSZ,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGVTALRM, (void(*)(int))daemon_exit_cleanly);
  signal(SIGPROF,   (void(*)(int))daemon_exit_cleanly);
  signal(SIGWINCH,  (void(*)(int))daemon_exit_cleanly);
  signal(SIGIO,     (void(*)(int))daemon_exit_cleanly);

  /*Close file descriptors and detactch process from shell as necessary*/
  if(opt.inetd_mode){
    daemon_inetd_process();
  }
  else{
    daemon_process();
  }

  /*
   * Re-create logger now process is detached (unless in inetd mode)
   * and configuration file has been read.
   */
  vanessa_logger_closelog(perdition_vl);
  if(opt.log_facility!=NULL && *(opt.log_facility)=='/'){
    if((perdition_vl=vanessa_logger_openlog_filename(
      opt.log_facility,
      LOG_IDENT,
      opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO),
      LOG_CONS
    ))==NULL){
      fprintf(stderr, "main: vanessa_logger_openlog_filename\n");
      fprintf(stderr, "Fatal error opening logger. Exiting.\n");
      daemon_exit_cleanly(-1);
    }
  }
  else {
    if((perdition_vl=vanessa_logger_openlog_syslog_byname(
      opt.log_facility,
      LOG_IDENT,
      opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO),
      LOG_CONS
    ))==NULL){
      fprintf(stderr, "main: vanessa_logger_openlog_syslog 2\n");
      fprintf(stderr, "Fatal error opening logger. Exiting.\n");
      daemon_exit_cleanly(-1);
    }
  }

  /*Seed the uname structure*/
  if((system_uname=(struct utsname *)malloc(sizeof(struct utsname)))==NULL){
    PERDITION_LOG(LOG_DEBUG,"main: malloc system_uname: %s",strerror(errno));
    PERDITION_LOG(LOG_ERR, "Fatal error allocating memory. Exiting.");
    daemon_exit_cleanly(-1);
  }
  if(uname(system_uname)<0){
    PERDITION_LOG(LOG_DEBUG, "main: uname");
    PERDITION_LOG(LOG_ERR, "Fatal error finding uname for system. Exiting");
    daemon_exit_cleanly(-1);
  }

  /*Set up protocol structure*/
  if((protocol=protocol_initialise(opt.protocol, protocol))==NULL){
    PERDITION_LOG(LOG_DEBUG, "main: protocol_initialise");
    PERDITION_LOG(LOG_ERR, "Fatal error intialising protocol. Exiting.");
    daemon_exit_cleanly(-1);
  }

  /*Set listen and outgoing port now the protocol structure is accessable*/
  if((opt.listen_port=(*(protocol->port))(opt.listen_port))==NULL){
    PERDITION_LOG(LOG_DEBUG, "main: protocol->port 1");
    PERDITION_LOG(LOG_ERR, "Fatal error finding port to listen on. Exiting.");
    daemon_exit_cleanly(-1);
  }
  if((opt.outgoing_port=(*(protocol->port))(opt.outgoing_port))==NULL){
    PERDITION_LOG(LOG_DEBUG, "main: protocol->port 2");
    PERDITION_LOG(LOG_ERR, "Fatal error finding port to connect to. Exiting.");
    daemon_exit_cleanly(-1);
  }

  /*
   * Log the options we will be running with.
   * If we are in inetd mode then only do this if debuging is turned on,
   * else dbuging is a bit too verbose.
   */
  if((!opt.quiet && !opt.inetd_mode) || opt.debug){
    if(log_options()){
      PERDITION_LOG(LOG_DEBUG, "main: log_options");
      PERDITION_LOG(LOG_ERR, "Fatal error loging options. Exiting.");
      daemon_exit_cleanly(-1);
    }
  }

  /*
   * Set up Logging for libvanessa_socket and libvanessa_adt
   */
  vanessa_socket_logger_set(perdition_vl);
  vanessa_adt_logger_set(perdition_vl);

  /*
   * If we are using the server's ok line then allocate a buffer to store it
   */ 
  if(opt.server_ok_line){
    if((server_ok_buf=(unsigned char *)malloc(
      sizeof(unsigned char)*MAX_LINE_LENGTH
    ))==NULL){
      PERDITION_LOG(LOG_DEBUG,"main: malloc server_ok_buf: %s",strerror(errno));
      PERDITION_LOG(LOG_ERR, "Fatal error allocating memory. Exiting.");
      daemon_exit_cleanly(-1);
    }
  }

  /*Open incoming socket as required*/
  if(opt.inetd_mode){
    client_in=0;
    client_out=1;
    *from_to_str='\0';
    *to_str='\0';
    *from_str='\0';
    peername=NULL;
    sockname=NULL;
  }
  else{
    if((client_in=vanessa_socket_server_connect(
      opt.listen_port, 
      opt.bind_address,
      opt.connection_limit, 
      &from,
      &to,
      0
    ))<0){
      PERDITION_LOG(LOG_DEBUG, "main: vanessa_socket_server_connect");
      PERDITION_LOG(LOG_ERR, "Fatal error accepting child connecion. Exiting.");
      daemon_exit_cleanly(-1);
    }
    client_out=client_in;
    snprintf(from_str, 17, "%s", inet_ntoa(from.sin_addr));
    snprintf(to_str,   17, "%s", inet_ntoa(to.sin_addr));
    snprintf(from_to_str, 36, "%s->%s ", from_str, to_str);
    peername=&from;
    sockname=&to;
  }

  /*Become someone else*/
  /*NB: We do this later if we are going to authenticate locally*/
#ifdef WITH_PAM_SUPPORT
  if(!opt.authenticate_in)
#endif /* WITH_PAM_SUPPORT */
    PERDITION_SET_UID_AND_GID;

  /*Seed rand*/
  srand(time(NULL)*getpid());
  rnd=rand();

  /*Speak to our client*/
  if(greeting(client_out, protocol, GREETING_ADD_NODENAME)){
    PERDITION_LOG(LOG_DEBUG, "main: greeting");
    PERDITION_LOG(
      LOG_ERR, 
      "Fatal error writing to client. %s Exiting child.",
      from_to_str
    );
    daemon_exit_cleanly(-1);
  }

  pw.pw_name=NULL;
  pw.pw_passwd=NULL;
  /* Authenticate the user*/
  for(;;){
    /*Read the USER and PASS lines from the client */
    if((status=(*(protocol->in_get_pw))(client_in, client_out, &pw, &tag))<0){
      PERDITION_LOG(LOG_DEBUG, "main: protocol->in_get_pw");
      PERDITION_LOG(
	LOG_ERR, 
	"Fatal Error reading authentication information from client \"%s\": "
	"Exiting child", 
	from_to_str
      );
      daemon_exit_cleanly(-1);
    }
    else if(status>0){
      PERDITION_LOG(
        LOG_DEBUG, 
        "Closing NULL session: %susername=%s", 
        from_to_str,
        str_null_safe(pw.pw_name)
      );
      daemon_exit_cleanly(0);
    }

    /*Read the server from the map, if we have a map*/
    if((username=strip_username(pw.pw_name, STATE_GET_SERVER))==NULL){
      PERDITION_DEBUG("main: strip_username STATE_GET_SERVER");
      PERDITION_LOG(
	LOG_ERR, 
	"Fatal error manipulating username for client \"%s\": Exiting child",
	from_str
      );
      daemon_exit_cleanly(-1);
    }

    if(
      opt.map_library!=NULL &&
      *(opt.map_library)!='\0' &&
      (server_port=getserver(username, dbserver_get))!=NULL
    ){
      char *host;

      port=server_port_get_port(server_port);
      servername=server_port_get_servername(server_port);
    
      if((host=strstr(servername, opt.domain_delimiter))!=NULL){
        /* The Username */
        if(opt.username_from_database){
          free(pw.pw_name);
	  *host='\0';
          if((pw.pw_name=strdup(servername))==NULL){
	    PERDITION_DEBUG("main: strdup");
            PERDITION_LOG(
	      LOG_ERR, 
	      "Fatal error manipulating username for client \"%s\": "
	      "Exiting child",
	      from_str
            );
	  }
        }

        /* The Host */
        servername = ++host;
      }
    }

    /*Use the default server if we have one and the servername is not set*/
    if((servername==NULL || round_robin_server) && opt.outgoing_server!=NULL){
      round_robin_server=1;
      rnd=(rnd+1)%vanessa_dynamic_array_get_count(opt.outgoing_server);
      server_port=vanessa_dynamic_array_get_element(opt.outgoing_server,rnd);
      servername=server_port_get_servername(server_port);
      port=server_port_get_port(server_port);
    }

    /*Use the default port if the port is not set*/
    if(port==NULL){
      port=opt.outgoing_port;
    }

    /*Log the session*/
    PERDITION_LOG(
      LOG_INFO, 
      "Connect: %suser=\"%s\" server=\"%s\" port=\"%s\"", 
      from_to_str,
      str_null_safe(pw.pw_name),
      str_null_safe(servername),
      str_null_safe(port)
    );

    /*Try again if we didn't get anything useful*/
    if(servername==NULL){
      sleep(PERDITION_AUTH_FAIL_SLEEP);
      if((*(protocol->write))(
        client_out, 
        NULL_FLAG,
	tag,
	protocol->type[PROTOCOL_ERR], 
	"Could not determine server"
      )<0){
        PERDITION_LOG(LOG_DEBUG, "main: protocol->write");
        PERDITION_LOG(LOG_ERR, "Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
      PERDITION_CLEAN_UP_MAIN;
      continue;
    }

#ifdef WITH_PAM_SUPPORT
    if(opt.authenticate_in){
      if((pw2.pw_name=strip_username(pw.pw_name, STATE_LOCAL_AUTH))==NULL){
        PERDITION_DEBUG("main: strip_username STATE_LOCAL_AUTH");
        PERDITION_LOG(
	  LOG_ERR, 
	  "Fatal error manipulating username for client \"%s\": Exiting child",
	  from_str
        );
        daemon_exit_cleanly(-1);
      }
      pw2.pw_passwd=pw.pw_passwd;

      if((status=protocol->in_authenticate(&pw2, client_out, tag))==0){
        PERDITION_LOG(LOG_DEBUG, "main: protocol->in_authenticate");
        PERDITION_LOG(
	  LOG_INFO, 
	  "Local authentication failure for client: Allowing retry."
        );
        PERDITION_CLEAN_UP_MAIN;
        continue;
      }
      else if(status<0){
        PERDITION_LOG(LOG_DEBUG, "main: pop3_in_authenticate");
        PERDITION_LOG(
	  LOG_ERR, 
	  "Fatal error authenticating to client locally. Exiting child."
        );
        daemon_exit_cleanly(-1);
      }
    
      /*
       * If local authentcation is used then now is the time to
       * Become someone else
       */
       PERDITION_SET_UID_AND_GID;
    }
#endif /* WITH_PAM_SUPPORT */

    /* Talk to the real pop server for the client*/
    if((server=vanessa_socket_client_src_open(
      opt.bind_address,
      NULL,
      servername, 
      port, 
      (opt.no_lookup?VANESSA_SOCKET_NO_LOOKUP:0)
    ))<0){
      PERDITION_LOG(LOG_DEBUG, "main: vanessa_socket_client_open");
      PERDITION_LOG(LOG_INFO, "Could not connect to server");
      sleep(PERDITION_ERR_SLEEP);
      if((*(protocol->write))(
        client_out,
        NULL_FLAG,
	tag,
	protocol->type[PROTOCOL_ERR], 
	"Could not connect to server"
      )<0){
        PERDITION_LOG(LOG_DEBUG, "main: protocol->write");
        PERDITION_LOG(LOG_ERR, "Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
      PERDITION_CLEAN_UP_MAIN;
      continue;
    }

    /*Authenticate the user with the pop server*/
    if((pw2.pw_name=strip_username(pw.pw_name, STATE_REMOTE_LOGIN))==NULL){
      PERDITION_DEBUG("main: strip_username STATE_REMOTE_LOGIN");
      PERDITION_LOG(
	LOG_ERR, 
	"Fatal error manipulating username for client \"%s\": Exiting child",
	from_str
      );
      daemon_exit_cleanly(-1);
    }
    pw2.pw_passwd=pw.pw_passwd;

    if(opt.server_ok_line){
      server_ok_buf_size=MAX_LINE_LENGTH-1;
    }
    status = (*(protocol->out_authenticate))(
      server, 
      server, 
      &pw2, 
      tag,
      protocol,
      server_ok_buf,
      &server_ok_buf_size
    );

    if(status==0){
      sleep(PERDITION_ERR_SLEEP);
      PERDITION_LOG(LOG_INFO, "Fail reauthentication for user %s", pw2.pw_name);
      quit(server, server, protocol);
      if(close(server)){
        PERDITION_LOG(LOG_DEBUG, "main: close(server) 2");
        PERDITION_LOG(
	  LOG_ERR, "Fatal error closing conection to client. Exiting child."
	);
	daemon_exit_cleanly(-1);
      }
      if(protocol->write(
        client_out, 
        NULL_FLAG,
        tag, 
        protocol->type[PROTOCOL_NO], 
        "Re-Authentecation Failure"
      )<0){
        PERDITION_LOG(LOG_DEBUG, "main: protocol->write");
        PERDITION_LOG(LOG_ERR, "Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
      PERDITION_CLEAN_UP_MAIN;
      continue;
    }
    else if(status<0){
      PERDITION_LOG(LOG_DEBUG, "main: protocol->out_authenticate %d", status);
      PERDITION_LOG(LOG_ERR, "Fatal error authenticating user. Exiting child.");
      daemon_exit_cleanly(-1);
    }

    /*If we get this far, dance for joy with lmf*/
    if(opt.server_ok_line){
      *(server_ok_buf+server_ok_buf_size)='\0';
      buffer=server_ok_buf;
      if(protocol->write(
        client_out, 
        WRITE_STR_NO_CLLF,
        tag, 
        NULL,
        server_ok_buf
      )<0){
        PERDITION_LOG(LOG_DEBUG, "main: protocol->write");
        PERDITION_LOG(LOG_ERR, "Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
    }
    else{
      if(protocol->write(
        client_out, 
        NULL_FLAG,
        tag, 
        protocol->type[PROTOCOL_OK],
        "You are so in"
      )<0){
        PERDITION_LOG(LOG_DEBUG, "main: protocol->write");
        PERDITION_LOG(LOG_ERR, "Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
    }

    break;
  }

  if(opt.server_ok_line){
     free(server_ok_buf);
  }

  /*We need a buffer for reads and writes to the server*/
  if((buffer=(unsigned char *)malloc(BUFFER_SIZE*sizeof(unsigned char)))==NULL){
    PERDITION_LOG(LOG_DEBUG, "main: malloc: %s, Exiting", strerror(errno));
    PERDITION_LOG(LOG_ERR, "Fatal error allocating memory. Exiting child.");
    daemon_exit_cleanly(-1);
  }

  /*Let the client talk to the real server*/
  if(vanessa_socket_pipe(
    server,
    server,
    client_in,
    client_out,
    buffer,
    BUFFER_SIZE,
    opt.timeout,
    &bytes_written,
    &bytes_read
  )<0){
    PERDITION_LOG(LOG_DEBUG, "main: vanessa_socket_pipe");
    PERDITION_LOG(LOG_ERR, "Fatal error piping data. Exiting child.");
    daemon_exit_cleanly(-1);
  }

  /*Time to leave*/
  PERDITION_LOG(
    LOG_INFO, 
    "Closing: %suser=%s %d %d", 
    from_to_str,
    pw.pw_name,
    bytes_read,
    bytes_written
  );
  getserver_closelib(handle);
  daemon_exit_cleanly(0);

  PERDITION_CLEAN_UP_MAIN;
  /*Here so compilers won't barf*/
  return(0);
}


/**********************************************************************
 * perdition_reread_handler
 * A signal handler that closes and opens the map libary,
 * reinitialising as necessary.
 * pre: sig: signal recieved by the process
 * post: signal handler reset for signal
 *       map library closed and opened
 *       This may casuse shutdown and initialisation of map to
 *       take place if appropriate symbols are defined in
 *       the library. See getserver.c for details.
 **********************************************************************/

static void perdition_reread_handler(int sig){
  extern options_t opt;

  getserver_closelib(handle);
  if(
    opt.map_library!=NULL && 
    getserver_openlib(
      opt.map_library, 
      opt.map_library_opt, 
      &handle, 
      &dbserver_get
    )<0
  ){
    PERDITION_LOG(LOG_DEBUG, "perdition_reread_handler: getserver_openlib");
    PERDITION_LOG(
      LOG_ERR, 
      "Fatal error reopening: %s. Exiting child.",
      opt.map_library
    );
    daemon_exit_cleanly(-1);
  }

  signal(sig, (void(*)(int))perdition_reread_handler);
}


/**********************************************************************
 * strip_username
 * Strip the domain name, all characters after opt.domain_delimiter,
 * from a username if it is permitted for a given state.
 * pre: username: username to strip domain from
 *      state: The current state. Should be one of STATE_GET_SERVER,
 *             STATE_LOCAL_AUTH or STATE_REMOTE_LOGIN.
 * post: if state&opt.strip_domain
 *         if state is STATE_GET_SERVER and opt.client_server_specification 
 *           return username
 *         else strip the domain name if it is present
 *       else return username
 * return: username, stripped as appropriate
 *         NULL on error
 * Note: to free any memory that may be used call strip_username_free()
 *       You should call this each time username changes as the result
 *       is chached internally and is not checked for staleness.
 **********************************************************************/

static char *__striped_username=NULL;
static flag_t __striped_username_alloced=0;

static char *__strip_username(char *username){
  char *end;
  size_t len;

  extern options_t opt;
  extern int errno;

  if(__striped_username==NULL){
    if((end=strstr(username, opt.domain_delimiter))==NULL){
      __striped_username=username;
    }
    else {
      len=end-username;
      if((__striped_username=(char *)malloc(len+1))==NULL){
	PERDITION_DEBUG_ERRNO("__strip_username: malloc", errno);
	return(NULL);
      }
      __striped_username_alloced=1;
      strncpy(__striped_username, username, len);
      *(__striped_username+len)='\0';
    }
  }

  return(__striped_username);
}

static char *strip_username(char *username, int state){
  extern options_t opt;

  if(!(opt.strip_domain&state)){
    return(username);
  }

  switch(state){
    case STATE_GET_SERVER:
      if(opt.client_server_specification){
        return(username);
      }
      else {
        return(__strip_username(username));
      }
    case STATE_LOCAL_AUTH:
      return(__strip_username(username));
    case STATE_REMOTE_LOGIN:
      return(__strip_username(username));
    default:
      PERDITION_DEBUG("strip_username: unknown state\n");
      return(NULL);
  }

  return(NULL);
}


/**********************************************************************
 * strip_username_free
 * Free any memory held by strip_username state
 * pre: none
 * post: If any memory has been allocated internally by strip_username()
 *       then it is freed
 * return: none
 **********************************************************************/

static void strip_username_free(void){
  if(__striped_username_alloced){
    free(__striped_username);
  }
  __striped_username=NULL;
}
