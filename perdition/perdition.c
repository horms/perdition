/**********************************************************************
 * perdition.c                                           September 1999
 * Horms                                             horms@verge.net.au
 *
 * Perdition, POP3 and IMAP4 proxy daemon
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2003  Horms
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


#ifdef HAVE_CONFIG_H
#include "config.h" 
#endif

#include <sys/utsname.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vanessa_socket.h>
#include <time.h>
#include <stdio.h>

#include "protocol.h"
#include "log.h"
#include "options.h"
#include "getserver.h"
#include "perdition_types.h"
#include "greeting.h"
#include "quit.h"
#include "config_file.h"
#include "config_file.h"
#include "server_port.h"
#include "username.h"
#include "ssl.h"
#include "setproctitle.h"
#include "imap4_tag.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/*Use uname information here and there to idinify this system*/
struct utsname *system_uname;

/* Local and Peer address information is gloabal so perditiondb
 * libaries can access this information
 */
struct sockaddr_in *peername;
struct sockaddr_in *sockname;

/*
 * Used for opening dynamic server lookup library
 * Kept global so they can be used in signal handlers
 */
static int (*dbserver_get)(const char *, const char *, char **, size_t *);
static void *handle;

static void perdition_reread_handler(int sig);

/* Macro to clean things up when we jump around in the main loop*/
#define PERDITION_CLEAN_UP_MAIN \
  if(username!=NULL && username!=pw.pw_name && username!=pw2.pw_name){ \
    free(username); \
  } \
  username=NULL; \
  if(pw2.pw_name!=NULL && pw2.pw_name!=pw.pw_name){ \
    free(pw2.pw_name); \
  } \
  pw2.pw_name=NULL; \
  pw2.pw_passwd=NULL; \
  if(pw.pw_name!=NULL){ \
    free(pw.pw_name); \
    pw.pw_name=NULL; \
  } \
  if(pw.pw_passwd!=NULL){ \
    free(pw.pw_passwd); \
    pw.pw_passwd=NULL;\
  } \
  if(pw2.pw_name!=NULL){ \
    free(pw2.pw_name); \
    pw2.pw_name=NULL; \
  } \
  pw2.pw_passwd=NULL; \
  if (!round_robin_server){ \
    server_port_destroy(server_port); \
  } \
  round_robin_server=0; \
  servername=NULL; \
  if(server_io!=NULL) { \
    io_close(server_io); \
    io_destroy(server_io); \
  } \
  server_io=NULL; \
  server_port=NULL; \
  token_destroy(&client_tag); \
  tls_state=0; \
  opt.capability = protocol->capability(opt.capability, \
    &(opt.mangled_capability), opt.ssl_mode, tls_state);

/* Macro to set the uid and gid */
#ifdef WITH_PAM_SUPPORT 
#define PERDITION_SET_UID_AND_GID \
  if(opt.debug && geteuid() && opt.authenticate_in){ \
    VANESSA_LOGGER_INFO( \
      "Warning: not invoked as root, local authentication may fail" \
    ); \
  } \
  if(!geteuid() && vanessa_socket_daemon_setid(opt.username, opt.group)){ \
    VANESSA_LOGGER_ERR("Fatal error setting group and userid. Exiting.");\
    vanessa_socket_daemon_exit_cleanly(-1); \
  }
#else
#define PERDITION_SET_UID_AND_GID \
  if(!geteuid() && vanessa_socket_daemon_setid(opt.username, opt.group)){ \
    VANESSA_LOGGER_ERR("Fatal error setting group and userid. Exiting.");\
    vanessa_socket_daemon_exit_cleanly(-1); \
  }
#endif

/* Macro to log session just after Authentication */
#define VANESSA_LOGGER_LOG_AUTH(_auth_log, _from_to_str,                   \
			_user, _servername, _port, _status)                \
	memset(_auth_log.log_str, 0, sizeof(_auth_log.log_str));           \
	snprintf(_auth_log.log_str, sizeof(_auth_log.log_str)-1,           \
			"Auth: %suser=\"%s\" server=\"%s\" port=\"%s\" "   \
			"status=\"%s\"",                                   \
			from_to_str, str_null_safe(_user),                 \
			str_null_safe(_servername),                        \
			str_null_safe(_port), str_null_safe(_status));     \
	VANESSA_LOGGER_LOG(LOG_NOTICE, _auth_log.log_str);                 \
	_auth_log.log_time=time(NULL) + opt.connect_relog;                 \
	set_proc_title("perdition: auth %s", str_null_safe(_status));

#define LOGIN_FAILED(_type, _reason)                                      \
{                                                                         \
	sleep(PERDITION_AUTH_FAIL_SLEEP);                                 \
	if(protocol->write(client_io, NULL_FLAG, client_tag,              \
				protocol->type[(_type)], 0,               \
				(_reason))<0){                            \
		VANESSA_LOGGER_DEBUG("protocol->write");                  \
		VANESSA_LOGGER_ERR("Fatal error writing to client. "      \
				"Exiting child.");                        \
		vanessa_socket_daemon_exit_cleanly(-1);                   \
	}                                                                 \
	VANESSA_LOGGER_LOG_AUTH(auth_log, from_to_str, pw.pw_name,        \
			servername, port,                                 \
			"failed: " _reason);                              \
}

/**********************************************************************
 * Muriel the main function
 **********************************************************************/

int main (int argc, char **argv, char **envp){
  vanessa_logger_t *vl;
  struct passwd pw = {NULL, NULL};
  struct passwd pw2 = {NULL, NULL};
  struct in_addr *to_addr;
  unsigned char *server_ok_buf=NULL;
  unsigned char *buffer;
  server_port_t *server_port=NULL;
  protocol_t *protocol=NULL;
  token_t *our_tag=NULL;
  token_t *client_tag=NULL;
  size_t server_ok_buf_size=0;
  flag_t tls_state=0;
  timed_log_t auth_log;
  char from_to_str[36];
  char from_str[17];
  char to_str[17];
  char *servername=NULL;
  char *username=NULL;
  char *port=NULL;
  io_t *client_io=NULL;
  io_t *server_io=NULL;
  FILE *fh;
  int bytes_written=0;
  int bytes_read=0;
  int status;
  int round_robin_server=0;
  int rnd;
  int s=-1;
  int g=-1;

#ifdef WITH_SSL_SUPPORT
  SSL_CTX *ssl_ctx=NULL;
#endif /* WITH_SSL_SUPPORT */

  extern struct sockaddr_in *peername;
  extern struct sockaddr_in *sockname;
  extern struct utsname *system_uname;
  extern options_t opt;

  /*
   * Create Logger
   */
  vl=vanessa_logger_openlog_filehandle(stderr, LOG_IDENT, LOG_DEBUG, LOG_CONS);
  if(!vl) {
    fprintf(stderr, "main: vanessa_logger_openlog_syslog\n"
                    "Fatal error opening logger. Exiting.\n");
    vanessa_socket_daemon_exit_cleanly(-1);
  }
  vanessa_logger_set(vl);

  /*Parse options*/
  options(argc, argv, OPT_FIRST_CALL);

  /* Initialise setting of proctitle */
  init_set_proc_title(argc, argv, envp);
  set_proc_title("perdition");

  /*
   * Update Logger
   */
  if(!opt.debug){
    vanessa_logger_change_max_priority(vl, opt.quiet?LOG_ERR:LOG_INFO);
  }

  /*Read congif file*/
  if(opt.config_file!=NULL){
    config_file_to_opt(opt.config_file);
  }

  /*Open the dbserver_get library, if we have a library*/
  if(
    getserver_openlib(
      opt.map_library,
      opt.map_library_opt,
      &handle,&dbserver_get
    )<0
  ){
    VANESSA_LOGGER_ERR_UNSAFE("dlopen of \"%s\" failed", 
      str_null_safe(opt.map_library));
    usage(-1);
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  /*Set signal handlers*/
  signal(SIGHUP,    perdition_reread_handler);
  signal(SIGINT,    vanessa_socket_daemon_exit_cleanly);
  signal(SIGQUIT,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGILL,    vanessa_socket_daemon_exit_cleanly);
  signal(SIGTRAP,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGIOT,    vanessa_socket_daemon_exit_cleanly);
  signal(SIGBUS,    vanessa_socket_daemon_exit_cleanly);
  signal(SIGFPE,    vanessa_socket_daemon_exit_cleanly);
  signal(SIGUSR1,   vanessa_socket_handler_noop);
  signal(SIGSEGV,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGUSR2,   vanessa_socket_handler_noop);
  signal(SIGPIPE,   SIG_IGN);
  signal(SIGALRM,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGTERM,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGCHLD,   vanessa_socket_handler_reaper);
  signal(SIGURG,    vanessa_socket_daemon_exit_cleanly);
  signal(SIGXCPU,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGXFSZ,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGVTALRM, vanessa_socket_daemon_exit_cleanly);
  signal(SIGPROF,   vanessa_socket_daemon_exit_cleanly);
  signal(SIGWINCH,  vanessa_socket_daemon_exit_cleanly);
  signal(SIGIO,     vanessa_socket_daemon_exit_cleanly);

  /* Set file descriptor to log to, if any */
  fh = NULL;
  if(opt.log_facility!=NULL) {
    if(*(opt.log_facility) == '-') {
      fh = stdout;
    }
    else if(*(opt.log_facility) == '+') {
      fh = stderr;
    }
  }

  /*Close file descriptors and detactch process from shell as necessary*/
  if(opt.inetd_mode || opt.no_daemon || fh != NULL){
    vanessa_socket_daemon_inetd_process();
  }
  else{
    vanessa_socket_daemon_process();
  }

  /*
   * Re-create logger now process is detached (unless in inetd mode)
   * and configuration file has been read.
   */
  vanessa_logger_unset();
  vanessa_logger_closelog(vl);
  if(fh != NULL) {
    vl=vanessa_logger_openlog_filehandle(fh, LOG_IDENT,
      opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO), LOG_CONS);
  }
  else if(opt.log_facility!=NULL && *(opt.log_facility)=='/'){
    vl=vanessa_logger_openlog_filename(opt.log_facility, LOG_IDENT,
      opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO), LOG_CONS);
  }
  else {
    vl=vanessa_logger_openlog_syslog_byname(opt.log_facility, LOG_IDENT,
      opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO), LOG_CONS);
  }
  if(vl == NULL) {
    fprintf(stderr, "main: vanessa_logger_openlog\n"
                    "Fatal error opening logger. Exiting.\n");
    vanessa_socket_daemon_exit_cleanly(-1);
  }
  vanessa_logger_set(vl);
 
  /* Create a PID file */


  /*Seed the uname structure*/
  if((system_uname=(struct utsname *)malloc(sizeof(struct utsname)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc system_uname");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }
  if(uname(system_uname)<0){
    VANESSA_LOGGER_DEBUG("uname");
    VANESSA_LOGGER_ERR("Fatal error finding uname for system. Exiting");
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  /*Set up protocol structure*/
  if((protocol=protocol_initialise(opt.protocol, protocol))==NULL){
    VANESSA_LOGGER_DEBUG("protocol_initialise");
    VANESSA_LOGGER_ERR("Fatal error intialising protocol. Exiting.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  /*Set listen and outgoing port now the protocol structure is accessable*/
  if((opt.listen_port=protocol->port(opt.listen_port))==NULL){
    VANESSA_LOGGER_DEBUG("protocol->port 1");
    VANESSA_LOGGER_ERR("Fatal error finding port to listen on. Exiting.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }
  if((opt.outgoing_port=protocol->port(opt.outgoing_port))==NULL){
    VANESSA_LOGGER_DEBUG("protocol->port 2");
    VANESSA_LOGGER_ERR("Fatal error finding port to connect to. Exiting.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  /* 
   * Set up a tag to use. 
   * Only used for IMAP based protocols, but it is harmless to have it
   * lying about
   */
  if(opt.protocol == PROTOCOL_IMAP4 || opt.protocol == PROTOCOL_IMAP4S) {
  	our_tag = imap4_tag_create();
  	if(!our_tag) {
	  	VANESSA_LOGGER_DEBUG("imap4_tag_create");
	  	VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
	  	vanessa_socket_daemon_exit_cleanly(-1);
  	}
  }
  else {
	  our_tag = NULL;
  }

#ifdef WITH_SSL_SUPPORT
  /*Set up the ssl mode*/
  opt.ssl_mode=protocol->encryption(opt.ssl_mode);
  opt.capability = protocol->capability(opt.capability, 
		  &(opt.mangled_capability), opt.ssl_mode, tls_state);

  if(opt.ssl_mode & SSL_LISTEN_MASK) {
    ssl_ctx = perdition_ssl_ctx(NULL, NULL, opt.ssl_cert_file, 
		    opt.ssl_key_file, opt.ssl_listen_ciphers);
    if(!ssl_ctx) {
      VANESSA_LOGGER_DEBUG_SSL_ERR("perdition_ssl_ctx");
      VANESSA_LOGGER_ERR("Fatal error establishing SSL context for listening");
      vanessa_socket_daemon_exit_cleanly(-1);
    }
  }
#else
  opt.capability = protocol->capability(opt.capability, 
		  &(opt.mangled_capability), SSL_MODE_NONE, SSL_MODE_NONE);
#endif /* WITH_SSL_SUPPORT */


  /*
   * Log the options we will be running with.
   * If we are in inetd mode then only do this if debuging is turned on,
   * else dbuging is a bit too verbose.
   */
  if((!opt.quiet && !opt.inetd_mode && !opt.no_daemon && !fh) || opt.debug){
    if(log_options()){
      VANESSA_LOGGER_DEBUG("log_options");
      VANESSA_LOGGER_ERR("Fatal error loging options. Exiting.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }
  }

  /*
   * If we are using the server's ok line then allocate a buffer to store it
   */ 
  if(opt.server_ok_line){
    if((server_ok_buf=(unsigned char *)malloc(
      sizeof(unsigned char)*MAX_LINE_LENGTH
    ))==NULL){
      VANESSA_LOGGER_DEBUG_ERRNO("malloc server_ok_buf");
      VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }
  }

  /*
   * Allocate the peername and sockanme structures
   */
  if((sockname=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc sockname");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }
  if((peername=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc peername");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }
  

  /* Open incoming socket as required */
  if(!opt.inetd_mode) {
    g = vanessa_socket_server_bind(opt.listen_port, opt.bind_address, 
 		    		   opt.no_lookup?VANESSA_SOCKET_NO_LOOKUP:0);
    if(g < 0) {
      VANESSA_LOGGER_DEBUG("vanessa_socket_server_bind");
      VANESSA_LOGGER_ERR("Fatal error listening for connections. Exiting.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }
  }

  /*
   * Become someone else
   * NB: We do this later if we are going to authenticate locally 
   */
#ifdef WITH_PAM_SUPPORT
  if(!opt.authenticate_in)
#endif
    PERDITION_SET_UID_AND_GID;

  /* Get an incoming connection */
  if(opt.inetd_mode){
    int namelen;

    if((client_io=io_create_fd(0, 1, PERDITION_LOG_STR_CLIENT))==NULL){
      VANESSA_LOGGER_DEBUG("io_create_fd 1");
      VANESSA_LOGGER_ERR("Fatal error setting IO. Exiting.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }

    namelen = sizeof(*peername);
    if(getpeername(0, (struct sockaddr *)peername, &namelen)){
      peername=NULL;
    }

    namelen = sizeof(*sockname);
    if(getsockname(1, (struct sockaddr *)sockname, &namelen)){
      sockname=NULL;
    }
  }
  else{
    s = vanessa_socket_server_accept(g, opt.connection_limit, peername, 
          sockname, 0);
    if(s < 0){
      VANESSA_LOGGER_DEBUG("vanessa_socket_server_accept");
      VANESSA_LOGGER_ERR("Fatal error accepting child connecion. Exiting.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }

    if((client_io=io_create_fd(s, s, PERDITION_LOG_STR_CLIENT))==NULL){
      VANESSA_LOGGER_DEBUG("io_create_fd 2");
      VANESSA_LOGGER_ERR("Fatal error setting IO. Exiting.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }
  }

  /* A child process, or process handling an inetd connection
   * should exit on reciept of a SIG PIPE.
   */
  signal(SIGPIPE,   vanessa_socket_daemon_exit_cleanly);

  /* Get the source and destination ip address as a string */
  if(peername!=NULL){
    snprintf(from_str, 17, "%s", inet_ntoa(peername->sin_addr));
  }
  else {
    *from_str='\0';
  }
  if(sockname!=NULL){
    snprintf(to_str,   17, "%s", inet_ntoa(sockname->sin_addr));
    to_addr=&(sockname->sin_addr);
  }
  else {
    *to_str='\0';
    to_addr=NULL;
  }
  if(peername!=NULL && sockname!=NULL){
    snprintf(from_to_str, 36, "%s->%s ", from_str, to_str);
  }
  else{
    *from_to_str='\0';
  }

  /*Seed rand*/
  srand(time(NULL)*getpid());
  rnd=rand();

  /*Log the session and change the proctitle*/
  if(opt.inetd_mode) {
    VANESSA_LOGGER_INFO_UNSAFE("Connect: %sinetd_pid=%d", 
          from_to_str, getppid());
  }
  else {
    VANESSA_LOGGER_INFO_UNSAFE("Connect: %s", from_to_str);
  }
  set_proc_title("perdition: connect");

#ifdef WITH_SSL_SUPPORT
  if(opt.ssl_mode & SSL_MODE_SSL_LISTEN) {
    client_io = perdition_ssl_server_connection(client_io, ssl_ctx);
    if(!client_io) {
      VANESSA_LOGGER_DEBUG("perdition_ssl_server_connection SSL");
      VANESSA_LOGGER_ERR("Fatal error establishing SSL connection to client");
      vanessa_socket_daemon_exit_cleanly(-1);
    }
  }
#endif /* WITH_SSL_SUPPORT */

  /*Speak to our client*/
  if(greeting(client_io, protocol, GREETING_ADD_NODENAME)){
    VANESSA_LOGGER_DEBUG("greeting");
    VANESSA_LOGGER_ERR_UNSAFE(
      "Fatal error writing to client. %sExiting child.",
      from_to_str
    );
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  pw.pw_name=NULL;
  pw.pw_passwd=NULL;
  /* Authenticate the user*/
  for(;;){
    /*Read the USER and PASS lines from the client */
    status=(*(protocol->in_get_pw))(client_io, &pw, &client_tag);
    token_flush();
    if(status<0){
      VANESSA_LOGGER_DEBUG("protocol->in_get_pw");
      VANESSA_LOGGER_ERR_UNSAFE(
	"Fatal Error reading authentication information from client \"%s\": "
	"Exiting child", 
	from_to_str
      );
      vanessa_socket_daemon_exit_cleanly(-1);
    }
    else if(status == 1){
      VANESSA_LOGGER_ERR_UNSAFE(
        "Closing NULL session: %susername=%s", 
        from_to_str,
        str_null_safe(pw.pw_name)
      );
      vanessa_socket_daemon_exit_cleanly(0);
    }
#ifdef WITH_SSL_SUPPORT
    else if((status == 2) && (opt.ssl_mode & SSL_MODE_TLS_LISTEN)){
      /* We have received a STLS */
      client_io = perdition_ssl_server_connection(client_io, ssl_ctx);
      if(!client_io) {
        VANESSA_LOGGER_DEBUG("perdition_ssl_server_connection TLS");
	VANESSA_LOGGER_ERR("Fatal error establishing TLS connection");
        vanessa_socket_daemon_exit_cleanly(-1);
      }
      tls_state |= SSL_MODE_TLS_LISTEN;
      opt.capability = protocol->capability(opt.capability,
            &(opt.mangled_capability), opt.ssl_mode, tls_state);
      continue;
    }
    else if(opt.login_disabled ||
		    ((status == 0) && (opt.ssl_mode & SSL_MODE_TLS_LISTEN) &&
		    (opt.ssl_mode & SSL_MODE_TLS_LISTEN_FORCE) &&
		    !(tls_state & SSL_MODE_TLS_LISTEN))) {
	    LOGIN_FAILED(PROTOCOL_NO, "Login Disabled");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
#endif /* WITH_SSL_SUPPORT */

    if((username=username_mangle(pw.pw_name, to_addr, STATE_GET_SERVER))==NULL){
      VANESSA_LOGGER_DEBUG("username_mangle STATE_GET_SERVER");
      VANESSA_LOGGER_ERR_UNSAFE(
	"Fatal error manipulating username for client \"%s\": Exiting child",
	from_str
      );
      vanessa_socket_daemon_exit_cleanly(-1);
    }

    /*Read the server from the map, if we have a map*/
    if(
      dbserver_get != NULL &&
      (server_port = getserver(username, from_str, to_str, 
			       peername==NULL?0:ntohs(peername->sin_port), 
			       sockname==NULL?0:ntohs(sockname->sin_port), 
			       dbserver_get)) != NULL
    ){
      char *host;

      port=server_port_get_port(server_port);
      servername=server_port_get_servername(server_port);
    
      if((host=strrstr(servername, opt.domain_delimiter))!=NULL){
        /* The Username */
        if(opt.username_from_database){
          if (pw.pw_name != username && pw.pw_name != NULL) {
            free(pw.pw_name);
            pw.pw_name = NULL;
          }
	  *host='\0';
          if((pw.pw_name=strdup(servername))==NULL){
	    VANESSA_LOGGER_DEBUG_ERRNO("strdup");
            VANESSA_LOGGER_ERR_UNSAFE(
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

    /*Try again if we didn't get anything useful*/
    if(servername==NULL){
	    LOGIN_FAILED(PROTOCOL_ERR, "Could not determine server");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }

#ifdef WITH_PAM_SUPPORT
    if(opt.authenticate_in){
      if((pw2.pw_name=username_mangle(pw.pw_name, 
            to_addr, STATE_LOCAL_AUTH))==NULL){
        VANESSA_LOGGER_DEBUG("username_mangle STATE_LOCAL_AUTH");
        VANESSA_LOGGER_ERR_UNSAFE(
	  "Fatal error manipulating username for client \"%s\": Exiting child",
	  from_str
        );
        vanessa_socket_daemon_exit_cleanly(-1);
      }
      pw2.pw_passwd=pw.pw_passwd;

      if((status=protocol->in_authenticate(&pw2, client_io, client_tag))==0){
        VANESSA_LOGGER_DEBUG("protocol->in_authenticate");
        VANESSA_LOGGER_INFO(
	  "Local authentication failure for client: Allowing retry."
        );
  	VANESSA_LOGGER_LOG_AUTH(auth_log, from_to_str, pw.pw_name, 
			servername, port, 
			"failed: local authentication failure");
        PERDITION_CLEAN_UP_MAIN;
        continue;
      }
      else if(status<0){
        VANESSA_LOGGER_DEBUG("pop3_in_authenticate");
        VANESSA_LOGGER_ERR(
	  "Fatal error authenticating to client locally. Exiting child."
        );
        vanessa_socket_daemon_exit_cleanly(-1);
      }

      /*
       * If local authentcation is used then now is the time to
       * Become someone else
       */
       PERDITION_SET_UID_AND_GID;
    }
#endif /* WITH_PAM_SUPPORT */

    /* Talk to the real pop server for the client*/
    s = vanessa_socket_client_src_open(opt.bind_address, NULL, servername, 
				    port, 
				    (opt.no_lookup?VANESSA_SOCKET_NO_LOOKUP:0));
    if(s < 0) {
	    VANESSA_LOGGER_DEBUG("vanessa_socket_client_open");
	    LOGIN_FAILED(PROTOCOL_ERR, "Could not connect to server");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }

    if((server_io=io_create_fd(s, s, PERDITION_LOG_STR_REAL))==NULL){
      VANESSA_LOGGER_DEBUG("io_create_fd 3");
      VANESSA_LOGGER_ERR("Fatal error setting IO. Exiting.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }

#ifdef WITH_SSL_SUPPORT
    if(opt.ssl_mode & SSL_MODE_SSL_OUTGOING) {
      server_io=perdition_ssl_client_connection(server_io, opt.ssl_ca_file, 
		      opt.ssl_ca_path, opt.ssl_outgoing_ciphers, servername);
      if(!server_io) {
        VANESSA_LOGGER_DEBUG("perdition_ssl_connection outgoing");
        VANESSA_LOGGER_ERR("Fatal error establishing SSL connection");
        vanessa_socket_daemon_exit_cleanly(-1);
      }
    }
#endif /* WITH_SSL_SUPPORT */

    /* Authenticate the user with the pop server */
    if((pw2.pw_name=username_mangle(pw.pw_name, 
          to_addr, STATE_REMOTE_LOGIN))==NULL){
      VANESSA_LOGGER_DEBUG("username_mangle STATE_REMOTE_LOGIN");
      VANESSA_LOGGER_ERR_UNSAFE(
	"Fatal error manipulating username for client \"%s\": Exiting child",
	from_str
      );
      vanessa_socket_daemon_exit_cleanly(-1);
    }
    pw2.pw_passwd=pw.pw_passwd;

    status = (*(protocol->out_setup))(server_io, &pw2, our_tag, protocol);
    if(status==0){
	    quit(server_io, protocol, our_tag);
	    LOGIN_FAILED(PROTOCOL_NO, "Connection Negotiation Failure");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
    else if(status<0){
      VANESSA_LOGGER_DEBUG_UNSAFE("protocol->out_setup %d", status);
      VANESSA_LOGGER_ERR("Fatal error negotiating setup. Exiting child.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }
#ifdef WITH_SSL_SUPPORT
    else if((opt.ssl_mode & SSL_MODE_TLS_OUTGOING) &&
          (status & PROTOCOL_S_STARTTLS)) {
      server_io=perdition_ssl_client_connection(server_io, opt.ssl_ca_file, 
		      opt.ssl_ca_path, opt.ssl_listen_ciphers, servername);
      if(!server_io) {
        VANESSA_LOGGER_DEBUG("perdition_ssl_connection outgoing");
        VANESSA_LOGGER_ERR("Fatal error establishing SSL connection");
        vanessa_socket_daemon_exit_cleanly(-1);
      }
      tls_state |= SSL_MODE_TLS_OUTGOING;
    }
    else if((opt.ssl_mode & SSL_MODE_TLS_OUTGOING) &&
		    (opt.ssl_mode & SSL_MODE_TLS_OUTGOING_FORCE) &&
		    !(status & PROTOCOL_S_STARTTLS)) {
	    quit(server_io, protocol, our_tag);
	    LOGIN_FAILED(PROTOCOL_NO, "TLS not present");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
#endif /* WITH_SSL_SUPPORT */

    if(opt.server_ok_line){
      server_ok_buf_size=MAX_LINE_LENGTH-1;
    }
    token_flush();
    status = (*(protocol->out_authenticate))(server_io, &pw2, our_tag, protocol,
      server_ok_buf, &server_ok_buf_size);
    if(status==0) {
	    quit(server_io, protocol, our_tag);
	    LOGIN_FAILED(PROTOCOL_NO, "Re-Authentication Failure");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
    if(status==2){
	    sleep(VANESSA_LOGGER_ERR_SLEEP);
	    LOGIN_FAILED(PROTOCOL_NO, "Login Disabled");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
    else if(status<0){
      VANESSA_LOGGER_DEBUG_UNSAFE("protocol->out_authenticate %d", status);
      VANESSA_LOGGER_ERR("Fatal error authenticating user. Exiting child.");
      vanessa_socket_daemon_exit_cleanly(-1);
    }

    if(opt.server_ok_line){
      *(server_ok_buf+server_ok_buf_size)='\0';
      buffer=server_ok_buf;
      if(protocol->write(client_io, WRITE_STR_NO_CLLF, client_tag, 
            NULL, 1, "%s", server_ok_buf)<0){
        VANESSA_LOGGER_DEBUG("protocol->write");
        VANESSA_LOGGER_ERR("Fatal error writing to client. Exiting child.");
        vanessa_socket_daemon_exit_cleanly(-1);
      }
    }
    else{
      if(protocol->write(client_io, NULL_FLAG, client_tag, 
            protocol->type[PROTOCOL_OK], 0, "You are so in")<0){
        VANESSA_LOGGER_DEBUG("protocol->write");
        VANESSA_LOGGER_ERR("Fatal error writing to client. Exiting child.");
        vanessa_socket_daemon_exit_cleanly(-1);
      }
    }

    break;
  }

  VANESSA_LOGGER_LOG_AUTH(auth_log, from_to_str, pw.pw_name, 
		  servername, port, "ok");

  if(opt.server_ok_line){
     free(server_ok_buf);
  }

  /*We need a buffer for reads and writes to the server*/
  if((buffer=(unsigned char *)malloc(BUFFER_SIZE*sizeof(unsigned char)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting child.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  /*Let the client talk to the real server*/
  if(io_pipe(server_io, client_io, buffer, BUFFER_SIZE, opt.timeout,
        &bytes_written, &bytes_read, &auth_log)<0){
    VANESSA_LOGGER_DEBUG("vanessa_socket_pipe");
    VANESSA_LOGGER_ERR("Fatal error piping data. Exiting child.");
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  /*Time to leave*/
  VANESSA_LOGGER_INFO_UNSAFE(
    "Close: %suser=\"%s\" received=%d sent=%d", 
    str_null_safe(from_to_str),
    str_null_safe(pw.pw_name),
    bytes_read,
    bytes_written
  );
  set_proc_title("perdition: close");

  getserver_closelib(handle);
  vanessa_socket_daemon_exit_cleanly(0);

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

  VANESSA_LOGGER_INFO_UNSAFE("Reloading map library \"%s\" with options \"%s\"",
    opt.map_library, opt.map_library_opt);
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
    VANESSA_LOGGER_DEBUG("getserver_openlib");
    VANESSA_LOGGER_ERR_UNSAFE("Fatal error reopening: %s. Exiting child.", 
      opt.map_library);
    vanessa_socket_daemon_exit_cleanly(-1);
  }

  signal(sig, (void(*)(int))perdition_reread_handler);
}
