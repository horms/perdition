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

#include "protocol.h"
#include "daemon.h"
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

#include <dmalloc.h>

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
  if(server_io!=NULL) { \
    io_close(server_io); \
    io_destroy(server_io); \
  } \
  server_io=NULL; \
  server_port=NULL; \
  token_destroy(&tag); 

/* Macro to set the uid and gid */
#ifdef WITH_PAM_SUPPORT 
#define PERDITION_SET_UID_AND_GID \
  if(opt.debug && geteuid() && opt.authenticate_in){ \
    PERDITION_INFO( \
      "Warning: not invoked as root, local authentication may fail" \
    ); \
  } \
  if(!geteuid() && daemon_setid(opt.username, opt.group)){ \
    PERDITION_ERR("Fatal error setting group and userid. Exiting.");\
    daemon_exit_cleanly(-1); \
  }
#else
#define PERDITION_SET_UID_AND_GID \
  if(!geteuid() && daemon_setid(opt.username, opt.group)){ \
    PERDITION_ERR("Fatal error setting group and userid. Exiting.");\
    daemon_exit_cleanly(-1); \
  }
#endif

/* Macro to log session just after Authentication */
#define PERDITION_LOG_AUTH(_from_to_str, _user, _servername, _port, _status) \
  PERDITION_LOG_UNSAFE( \
    LOG_NOTICE, \
    "Auth: %suser=\"%s\" server=\"%s\" port=\"%s\" status=\"%s\"",  \
    from_to_str, \
    str_null_safe(_user), \
    str_null_safe(_servername), \
    str_null_safe(_port), \
    str_null_safe(_status) \
  );

#ifdef WITH_SSL_SUPPORT
io_t *perdition_ssl_connection(
  io_t *io,
  SSL_CTX *ssl_ctx,
  flag_t flag
);

SSL_CTX *perdition_ssl_ctx(const char *cert, const char *privkey);
#endif /* WITH_SSL_SUPPORT */

/**********************************************************************
 * Muriel the main function
 **********************************************************************/

int main (int argc, char **argv){
  struct passwd pw = {NULL, NULL};
  struct passwd pw2 = {NULL, NULL};
  struct in_addr *to_addr;
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
  char *username=NULL;
  char *port=NULL;
  io_t *client_io=NULL;
  io_t *server_io=NULL;
  int bytes_written=0;
  int bytes_read=0;
  int status;
  int round_robin_server=0;
  int rnd;
  int s;

#ifdef WITH_SSL_SUPPORT
  SSL_CTX *ssl_ctx=NULL;
  SSL *ssl;
  X509 *server_cert;
#endif /* WITH_SSL_SUPPORT */

  extern struct sockaddr_in *peername;
  extern struct sockaddr_in *sockname;
  extern struct utsname *system_uname;
  extern options_t opt;

  /*
   * Create Logger
   */
  if((perdition_vl=vanessa_logger_openlog_filehandle(
    stdout,
    LOG_IDENT,
    LOG_DEBUG,
    LOG_CONS
  ))==NULL){
    fprintf(stderr, "main: vanessa_logger_openlog_syslog\n"
                    "Fatal error opening logger. Exiting.\n");
    daemon_exit_cleanly(-1);
  }

  /*Parse options*/
  options(argc, argv, OPT_FIRST_CALL);

  /*
   * Update Logger
   */
  if(!opt.debug){
    vanessa_logger_closelog(perdition_vl);
    if((perdition_vl=vanessa_logger_openlog_filehandle(
      stdout,
      LOG_IDENT,
      opt.quiet?LOG_ERR:LOG_INFO,
      LOG_CONS
    ))==NULL){
      fprintf(stderr, "main: vanessa_logger_openlog_syslog\n"
                      "Fatal error opening logger. Exiting.\n");
      daemon_exit_cleanly(-1);
    }
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
    PERDITION_ERR_UNSAFE("dlopen of \"%s\" failed", 
      str_null_safe(opt.map_library));
    usage(-1);
    daemon_exit_cleanly(-1);
  }

#ifdef WITH_SSL_SUPPORT
  if(opt.ssl_mode&SSL_MODE_SSL_LISTEN &&
      (ssl_ctx=perdition_ssl_ctx(opt.ssl_cert_file, opt.ssl_key_file))==NULL){
    PERDITION_DEBUG_SSL_ERR("perdition_ssl_ctx 1");
    daemon_exit_cleanly(-1);
  }
#endif /* WITH_SSL_SUPPORT */

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
      fprintf(stderr, "main: vanessa_logger_openlog_filename\n"
                      "Fatal error opening logger. Exiting.\n");
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
      fprintf(stderr, "main: vanessa_logger_openlog_syslog 2\n"
                      "Fatal error opening logger. Exiting.\n");
      daemon_exit_cleanly(-1);
    }
  }

  /*Seed the uname structure*/
  if((system_uname=(struct utsname *)malloc(sizeof(struct utsname)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc system_uname");
    PERDITION_ERR("Fatal error allocating memory. Exiting.");
    daemon_exit_cleanly(-1);
  }
  if(uname(system_uname)<0){
    PERDITION_DEBUG("uname");
    PERDITION_ERR("Fatal error finding uname for system. Exiting");
    daemon_exit_cleanly(-1);
  }

  /*Set up protocol structure*/
  if((protocol=protocol_initialise(opt.protocol, protocol))==NULL){
    PERDITION_DEBUG("protocol_initialise");
    PERDITION_ERR("Fatal error intialising protocol. Exiting.");
    daemon_exit_cleanly(-1);
  }

  /*Set listen and outgoing port now the protocol structure is accessable*/
  if((opt.listen_port=(*(protocol->port))(opt.listen_port))==NULL){
    PERDITION_DEBUG("protocol->port 1");
    PERDITION_ERR("Fatal error finding port to listen on. Exiting.");
    daemon_exit_cleanly(-1);
  }
  if((opt.outgoing_port=(*(protocol->port))(opt.outgoing_port))==NULL){
    PERDITION_DEBUG("protocol->port 2");
    PERDITION_ERR("Fatal error finding port to connect to. Exiting.");
    daemon_exit_cleanly(-1);
  }

  /*
   * Log the options we will be running with.
   * If we are in inetd mode then only do this if debuging is turned on,
   * else dbuging is a bit too verbose.
   */
  if((!opt.quiet && !opt.inetd_mode) || opt.debug){
    if(log_options()){
      PERDITION_DEBUG("log_options");
      PERDITION_ERR("Fatal error loging options. Exiting.");
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
      PERDITION_DEBUG_ERRNO("malloc server_ok_buf");
      PERDITION_ERR("Fatal error allocating memory. Exiting.");
      daemon_exit_cleanly(-1);
    }
  }

  /*
   * Allocate the peername and sockanme structures
   */
  if((sockname=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc sockname");
    PERDITION_ERR("Fatal error allocating memory. Exiting.");
    daemon_exit_cleanly(-1);
  }
  if((peername=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc peername");
    PERDITION_ERR("Fatal error allocating memory. Exiting.");
    daemon_exit_cleanly(-1);
  }
  

  /*Open incoming socket as required*/
  if(opt.inetd_mode){
    int namelen;

    if((client_io=io_create_fd(0, 1))==NULL){
      PERDITION_DEBUG("io_create_fd 1");
      PERDITION_ERR("Fatal error setting IO. Exiting.");
      daemon_exit_cleanly(-1);
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
    if((s=vanessa_socket_server_connect(
      opt.listen_port, 
      opt.bind_address,
      opt.connection_limit, 
      peername,
      sockname,
      0
    ))<0){
      PERDITION_DEBUG("vanessa_socket_server_connect");
      PERDITION_ERR("Fatal error accepting child connecion. Exiting.");
      daemon_exit_cleanly(-1);
    }

    if((client_io=io_create_fd(s, s))==NULL){
      PERDITION_DEBUG("io_create_fd 2");
      PERDITION_ERR("Fatal error setting IO. Exiting.");
      daemon_exit_cleanly(-1);
    }
  }

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

  /*Become someone else*/
  /*NB: We do this later if we are going to authenticate locally*/
#ifdef WITH_PAM_SUPPORT
  if(!opt.authenticate_in)
#endif /* WITH_PAM_SUPPORT */
    PERDITION_SET_UID_AND_GID;

  /*Seed rand*/
  srand(time(NULL)*getpid());
  rnd=rand();

  /*Log the session*/
  if(opt.inetd_mode) {
    PERDITION_INFO_UNSAFE("Connect: %sinetd_pid=%d", from_to_str, getppid());
  }
  else {
    PERDITION_INFO_UNSAFE("Connect: %s", from_to_str);
  }

#ifdef WITH_SSL_SUPPORT
  if(opt.ssl_mode&SSL_MODE_SSL_LISTEN && (client_io=perdition_ssl_connection(
      client_io, ssl_ctx, PERDITION_SERVER))==NULL){
    PERDITION_DEBUG("perdition_ssl_connection 1");
    daemon_exit_cleanly(-1);
  }
#endif /* WITH_SSL_SUPPORT */

  /*Speak to our client*/
  if(greeting(client_io, protocol, GREETING_ADD_NODENAME)){
    PERDITION_DEBUG("greeting");
    PERDITION_ERR_UNSAFE(
      "Fatal error writing to client. %sExiting child.",
      from_to_str
    );
    daemon_exit_cleanly(-1);
  }

  pw.pw_name=NULL;
  pw.pw_passwd=NULL;
  /* Authenticate the user*/
  for(;;){
    /*Read the USER and PASS lines from the client */
    if((status=(*(protocol->in_get_pw))(client_io, &pw, &tag))<0){
      PERDITION_DEBUG("protocol->in_get_pw");
      PERDITION_ERR_UNSAFE(
	"Fatal Error reading authentication information from client \"%s\": "
	"Exiting child", 
	from_to_str
      );
      daemon_exit_cleanly(-1);
    }
    else if(status>0){
      PERDITION_ERR_UNSAFE(
        "Closing NULL session: %susername=%s", 
        from_to_str,
        str_null_safe(pw.pw_name)
      );
      daemon_exit_cleanly(0);
    }

    if((username=username_mangle(pw.pw_name, to_addr, STATE_GET_SERVER))==NULL){
      PERDITION_DEBUG("username_mangle STATE_GET_SERVER");
      PERDITION_ERR_UNSAFE(
	"Fatal error manipulating username for client \"%s\": Exiting child",
	from_str
      );
      daemon_exit_cleanly(-1);
    }

    /*Read the server from the map, if we have a map*/
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
	    PERDITION_DEBUG_ERRNO("strdup");
            PERDITION_ERR_UNSAFE(
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
      sleep(PERDITION_AUTH_FAIL_SLEEP);
      if((*(protocol->write))(
        client_io, 
        NULL_FLAG,
	tag,
	protocol->type[PROTOCOL_ERR], 
	"Could not determine server"
      )<0){
        PERDITION_DEBUG("protocol->write");
        PERDITION_ERR("Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
      PERDITION_CLEAN_UP_MAIN;
      continue;
    }

#ifdef WITH_PAM_SUPPORT
    if(opt.authenticate_in){
      if((pw2.pw_name=username_mangle(pw.pw_name, 
            to_addr, STATE_LOCAL_AUTH))==NULL){
        PERDITION_DEBUG("username_mangle STATE_LOCAL_AUTH");
        PERDITION_ERR_UNSAFE(
	  "Fatal error manipulating username for client \"%s\": Exiting child",
	  from_str
        );
        daemon_exit_cleanly(-1);
      }
      pw2.pw_passwd=pw.pw_passwd;

      if((status=protocol->in_authenticate(&pw2, client_io, tag))==0){
        PERDITION_DEBUG("protocol->in_authenticate");
        PERDITION_INFO(
	  "Local authentication failure for client: Allowing retry."
        );
        PERDITION_CLEAN_UP_MAIN;
        continue;
      }
      else if(status<0){
        PERDITION_DEBUG("pop3_in_authenticate");
        PERDITION_ERR(
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
    if((s=vanessa_socket_client_src_open(
      opt.bind_address,
      NULL,
      servername, 
      port, 
      (opt.no_lookup?VANESSA_SOCKET_NO_LOOKUP:0)
    ))<0){
      PERDITION_DEBUG("vanessa_socket_client_open");
      PERDITION_INFO("Could not connect to server");
      sleep(PERDITION_ERR_SLEEP);
      if((*(protocol->write))(
        client_io,
        NULL_FLAG,
	tag,
	protocol->type[PROTOCOL_ERR], 
	"Could not connect to server"
      )<0){
        PERDITION_DEBUG("protocol->write");
        PERDITION_ERR("Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
      PERDITION_CLEAN_UP_MAIN;
      continue;
    }

    if((server_io=io_create_fd(s, s))==NULL){
      PERDITION_DEBUG("io_create_fd 3");
      PERDITION_ERR("Fatal error setting IO. Exiting.");
      daemon_exit_cleanly(-1);
    }

#ifdef WITH_SSL_SUPPORT
    if(opt.ssl_mode&SSL_MODE_SSL_OUTGOING){
      if((ssl_ctx=perdition_ssl_ctx(NULL, NULL))==NULL){
        PERDITION_DEBUG_SSL_ERR("perdition_ssl_ctx 2");
        daemon_exit_cleanly(-1);
      }

      if((server_io=perdition_ssl_connection(
        server_io, 
        ssl_ctx,
        PERDITION_CLIENT
      ))==NULL){
        PERDITION_DEBUG("perdition_ssl_connection 2");
        daemon_exit_cleanly(-1);
      }
  
      if((ssl=io_get_ssl(server_io))==NULL){
        PERDITION_DEBUG("vanessa_socket_get_ssl");
        daemon_exit_cleanly(-1);
      }

      PERDITION_DEBUG_UNSAFE("SSL connection using %s", SSL_get_cipher(ssl));

      if((server_cert=SSL_get_peer_certificate(ssl))==NULL){
        PERDITION_DEBUG_SSL_ERR("SSL_get_peer_certificate");
        PERDITION_ERR("No Server certificate");
        daemon_exit_cleanly(-1);
      }

      {
        char *str;

        PERDITION_DEBUG("Server certificate:");
  
        str=X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
        if(str==NULL){
          PERDITION_DEBUG_SSL_ERR("X509_NAME_oneline");
          PERDITION_ERR("Error reading certificate subject name");
          daemon_exit_cleanly(-1);
        }
        PERDITION_DEBUG_UNSAFE("subject: %s", str);
        free(str);
  
        str=X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
        if(str==NULL){
          PERDITION_DEBUG_SSL_ERR("X509_NAME_oneline");
          PERDITION_ERR("Error reading certificate issuer name");
          daemon_exit_cleanly(-1);
        }
        PERDITION_DEBUG_UNSAFE("issuer: %s", str);
        free(str);
  
        /* We could do all sorts of certificate verification stuff here before
         *        deallocating the certificate. */
  
        X509_free (server_cert);
      }
    }
#endif /* WITH_SSL_SUPPORT */

    /* Authenticate the user with the pop server */
    if((pw2.pw_name=username_mangle(pw.pw_name, 
          to_addr, STATE_REMOTE_LOGIN))==NULL){
      PERDITION_DEBUG("username_mangle STATE_REMOTE_LOGIN");
      PERDITION_ERR_UNSAFE(
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
      server_io, 
      &pw2, 
      tag,
      protocol,
      server_ok_buf,
      &server_ok_buf_size
    );

    if(status==0){
      sleep(PERDITION_ERR_SLEEP);
      PERDITION_LOG_AUTH(from_to_str, pw.pw_name, servername, port, "failed");
      quit(server_io, protocol);
      if(io_close(server_io)){
        PERDITION_DEBUG("io_close 2");
        PERDITION_ERR(
	  "Fatal error closing connection to client. Exiting child."
	);
	daemon_exit_cleanly(-1);
      }
      if(protocol->write(
        client_io, 
        NULL_FLAG,
        tag, 
        protocol->type[PROTOCOL_NO], 
        "Re-Authentication Failure"
      )<0){
        PERDITION_DEBUG("protocol->write");
        PERDITION_ERR("Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
      PERDITION_CLEAN_UP_MAIN;
      continue;
    }
    else if(status<0){
      PERDITION_DEBUG_UNSAFE("protocol->out_authenticate %d", status);
      PERDITION_ERR("Fatal error authenticating user. Exiting child.");
      daemon_exit_cleanly(-1);
    }

    if(opt.server_ok_line){
      *(server_ok_buf+server_ok_buf_size)='\0';
      buffer=server_ok_buf;
      if(protocol->write(
        client_io, 
        WRITE_STR_NO_CLLF,
        tag, 
        NULL,
        server_ok_buf
      )<0){
        PERDITION_DEBUG("protocol->write");
        PERDITION_ERR("Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
    }
    else{
      if(protocol->write(
        client_io, 
        NULL_FLAG,
        tag, 
        protocol->type[PROTOCOL_OK],
        "You are so in"
      )<0){
        PERDITION_DEBUG("protocol->write");
        PERDITION_ERR("Fatal error writing to client. Exiting child.");
        daemon_exit_cleanly(-1);
      }
    }

    break;
  }

  PERDITION_LOG_AUTH(from_to_str, pw.pw_name, servername, port, "ok");

  if(opt.server_ok_line){
     free(server_ok_buf);
  }

  /*We need a buffer for reads and writes to the server*/
  if((buffer=(unsigned char *)malloc(BUFFER_SIZE*sizeof(unsigned char)))==NULL){
    PERDITION_DEBUG_ERRNO("malloc");
    PERDITION_ERR("Fatal error allocating memory. Exiting child.");
    daemon_exit_cleanly(-1);
  }

  /*Let the client talk to the real server*/
  if(io_pipe(
    server_io,
    client_io,
    buffer,
    BUFFER_SIZE,
    opt.timeout,
    &bytes_written,
    &bytes_read
  )<0){
    PERDITION_DEBUG("vanessa_socket_pipe");
    PERDITION_ERR("Fatal error piping data. Exiting child.");
    daemon_exit_cleanly(-1);
  }

  /*Time to leave*/
  PERDITION_INFO_UNSAFE(
    "Close: %suser=\"%s\" received=%d sent=%d", 
    str_null_safe(from_to_str),
    str_null_safe(pw.pw_name),
    bytes_read,
    bytes_written
  );
  getserver_closelib(handle);
  daemon_exit_cleanly(0);

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

  PERDITION_INFO_UNSAFE("Reloading map library \"%s\" with options \"%s\"",
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
    PERDITION_DEBUG("getserver_openlib");
    PERDITION_ERR_UNSAFE("Fatal error reopening: %s. Exiting child.", 
      opt.map_library);
    daemon_exit_cleanly(-1);
  }

  signal(sig, (void(*)(int))perdition_reread_handler);
}


#ifdef WITH_SSL_SUPPORT
/**********************************************************************
 * perdition_ssl_connection
 * Change a stdio bassed connection into an SSL connection
 * io: io_t to change
 * ssl_cts: SSL Context to use
 * flag: If PERDITION_CLIENT the io is a client that has connected to
 *       a server and SSL_connect() will be called. If PERDITION_SERVER
 *       then the io is a serve rthat has accepted a connection and
 *       SSL_accept will be called. There are no other valid values
 *       for flag.
 * post: io_t has an ssl object associated with it and SSL is intiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *perdition_ssl_connection(
  io_t *io,
  SSL_CTX *ssl_ctx,
  flag_t flag
){
  io_t *new_io=NULL;
  SSL *ssl=NULL;
  
  if((ssl=SSL_new(ssl_ctx))==NULL){
    PERDITION_DEBUG_SSL_ERR("SSL_new");
    goto bail;
  }

  /* Set up io object that will use SSL */
  if((new_io=io_create_ssl(ssl, io_get_rfd(io), io_get_wfd(io)))==NULL){
    PERDITION_DEBUG("io_create_ssl");
    goto bail;
  }

  io_destroy(io);

  /* Get for TLS/SSL handshake */
  if(flag&PERDITION_CLIENT){
    SSL_set_connect_state(ssl);
    if(SSL_connect(ssl)<=0){
      PERDITION_DEBUG_SSL_ERR("SSL_connect");
      goto bail;
    }
  }
  else {
    SSL_set_accept_state(ssl);
    if(SSL_accept(ssl)<=0){
      PERDITION_DEBUG_SSL_ERR("SSL_accept");
      goto bail;
    }
  }

  PERDITION_DEBUG_UNSAFE("SSL connection using %s", SSL_get_cipher(ssl));

  return(new_io);

bail:
  if(new_io==NULL)
    SSL_free(ssl);
  else
    io_destroy(new_io);
  return(NULL);
}


/**********************************************************************
 * perdition_ssl_ctx
 * Create an SSL context
 * pre: cert: certificate to use. May be NULL if privkey is NULL. 
 *            Should the path to a PEM file if non-NULL and the
 *            first item in the PEM file will be used as the 
 *            certificate.
 *      privkey: private key to use May be NULL if cert is NULL. 
 *               Should the path to a PEM file if non-NULL and the
 *               first item in the PEM file will be used as the 
 *               private key.
 * post: If SSL is initiated and a context is created
 *       If cert is non-NULL then this certificate file is loaded
 *       If privkey is non-NULL then this private key file is loaded
 *       If cert and privkey are non-NULL then check private key
 *       against certificate.
 *       Note: If either cert of privkey are non-NULL then both must
 *       be non-NULL.
 **********************************************************************/

SSL_CTX *perdition_ssl_ctx(const char *cert, const char *privkey){
  SSL_METHOD *ssl_method;
  SSL_CTX *ssl_ctx;

  /* 
   * If either the certificate or private key is non-NULL the
   * other should be too
   */

  if(cert==NULL && privkey!=NULL){
    PERDITION_DEBUG("Certificate is NULL but private key is non-NULL");
    return(NULL);
  }

  if(privkey==NULL && cert!=NULL){
    PERDITION_DEBUG("Private key is NULL but certificate is non-NULL");
    return(NULL);
  }

  /*
   * Initialise an SSL context
   */

  SSLeay_add_ssl_algorithms();
  ssl_method = SSLv23_method();
  SSL_load_error_strings();

  if((ssl_ctx=SSL_CTX_new(ssl_method))==NULL){
    PERDITION_DEBUG_SSL_ERR("SSL_CTX_new");
    return(NULL);
  }

  /*
   * If the certificate or private key is NULL (one is implied by
   * the other, and it has been checked) then there is no
   * more proccessing to be done
   */
  if(cert==NULL){
    return(ssl_ctx);
  }

  /*
   * Load and check the certificate and private key
   */

  if (SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM)<=0){
    PERDITION_DEBUG_SSL_ERR_UNSAFE("SSL_CTX_use_certificate_file: \"%s\"", 
      cert);
    PERDITION_ERR_UNSAFE("Error loading certificate file \"%s\"", cert);
    SSL_CTX_free(ssl_ctx);
    return(NULL);
  }
 
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, privkey, SSL_FILETYPE_PEM)<= 0){
    PERDITION_DEBUG_SSL_ERR_UNSAFE("SSL_CTX_use_PrivateKey_file: \"%s\"", 
      privkey);
    PERDITION_ERR_UNSAFE("Error loading pricvate key file \"%s\"", privkey);
    SSL_CTX_free(ssl_ctx);
    return(NULL);
  }
  
  if(!SSL_CTX_check_private_key(ssl_ctx)){
    PERDITION_DEBUG("Private key does not match the certificate public key.");
    SSL_CTX_free(ssl_ctx);
    return(NULL);
  }

  return(ssl_ctx);
}
#endif /* sl_ctxITH_SSL_SUPPORT */
