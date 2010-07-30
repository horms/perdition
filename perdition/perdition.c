/**********************************************************************
 * perdition.c                                           September 1999
 * Horms                                             horms@verge.net.au
 *
 * Perdition, POP3 and IMAP4 proxy daemon
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
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vanessa_socket.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>

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
#include "sock.h"
#include "setproctitle.h"
#include "imap4_tag.h"
#include "perdition_globals.h"

/* limits.h should be sufficient on most systems 
 * http://www.opengroup.org/onlinepubs/007908799/headix.html */
#include <limits.h>
#if 0
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#ifdef __FreeBSD__
#if __FreeBSD_version < 500112
#include <machine/limits.h> /* For ULONG_MAX on FreeBSD */
#else
#include <sys/limits.h>
#endif
#endif
#endif
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif

/*Use uname information here and there to identify this system*/
struct utsname *system_uname;

/* Local and Peer address information is global so perditiondb
 * libraries can access this information
 */
struct sockaddr_storage *peername;
struct sockaddr_storage *sockname;

/* PID file that has been created */
static char *pid_file;

/* Programme name */
static char *progname;

/*
 * Used for opening dynamic server lookup library
 * Kept global so they can be used in signal handlers
 */
static int (*dbserver_get)(const char *, const char *, char **, size_t *);
static int (*dbserver_get2)(const char *, const char *, char **, 
		char **, char**);
static void *handle;

static void perdition_reread_handler(int sig);
static void perdition_exit_cleanly(int i);

static int write_pid_file(const char *pidfilename, const char *username,
		const char *group);
static int perdition_chown(const char *path, const char *username, 
		const char *group);


/* Macro to clean things up when we jump around in the main loop*/
#define PERDITION_CLEAN_UP_MAIN \
  auth_free_data(&auth); \
  auth_zero(&auth); \
  if (!round_robin_server){ \
    user_server_port_destroy(usp); \
  } \
  round_robin_server=0; \
  servername=NULL; \
  if(server_io!=NULL) { \
    io_close(server_io); \
    io_destroy(server_io); \
  } \
  server_io=NULL; \
  usp=NULL; \
  token_destroy(&client_tag); \
  tls_state=0;

/* Macro to set the uid and gid */
#define PERDITION_SET_UID_AND_GID \
  if(!geteuid() && vanessa_socket_daemon_setid(opt.username, opt.group)){ \
    VANESSA_LOGGER_ERR("Fatal error setting group and userid. Exiting.");\
    perdition_exit_cleanly(-1); \
  }

struct quoted_str {
	const char *quote, *str;
};

static struct quoted_str quote_str(const char *in)
{
	struct quoted_str out;

	if (in) {
		out.quote = "\"";
		out.str = in;
	} else {
		out.quote = "";
		out.str = "NONE";
	}

	return out;
}

static void 
perdition_log_auth(timed_log_t *auth_log, const char *from_to_host_str,
		struct auth *auth, const char *servername, const char *port,
		const char *reason, int ssl_mode, int tls_state)
{
	const char *eu_ssl, *rs_ssl, *pw_head, *pw_body, *pw_tail;
	struct quoted_str authorisation_id = quote_str(auth->authorisation_id);
	char *protocol = NULL;

	if (opt.debug &&
	    ((!strcmp(reason, "ok") && (opt.log_passwd & LOG_PASSWD_OK)) ||
	     (opt.log_passwd & LOG_PASSWD_FAIL))) {
		pw_body = auth->passwd;
		pw_head = " passwd=\"";
		pw_tail = "\"";
	}
	else
		pw_head = pw_body = pw_tail = "";

	if (ssl_mode & SSL_MODE_SSL_LISTEN)
		eu_ssl = "ssl";
	else if (tls_state & SSL_MODE_TLS_LISTEN)
		eu_ssl = "starttls";
	else
		eu_ssl = "plaintext";

	if (ssl_mode & SSL_MODE_SSL_OUTGOING)
		rs_ssl = "ssl";
	else if (tls_state & SSL_MODE_TLS_OUTGOING)
		rs_ssl = "starttls";
	else
		rs_ssl = "plaintext";

	protocol = protocol_list(protocol, NULL, opt.protocol);

	memset(auth_log->log_str, 0, sizeof(auth_log->log_str));
	snprintf(auth_log->log_str, sizeof(auth_log->log_str),
			"Auth:%s client-secure=%s authorisation_id=%s%s%s "
			"authentication_id=\"%s\"%s%s%s "
			"server=\"%s:%s\" protocol=%s "
			"server-secure=%s status=\"%s\"",
			from_to_host_str, eu_ssl, authorisation_id.quote,
			authorisation_id.str, authorisation_id.quote,
			str_null_safe(auth->authentication_id),
			pw_head, pw_body, pw_tail, str_null_safe(servername),
			str_null_safe(port), str_null_safe(protocol),
			rs_ssl, str_null_safe(reason));
	auth_log->log_time = time(NULL) + opt.connect_relog;

	free(protocol);

	VANESSA_LOGGER_LOG(LOG_NOTICE, auth_log->log_str);

	set_proc_title("%s: connect (%s)", progname,
		       str_null_safe(auth_get_authorisation_id(auth)));
}

#define PERDITION_LOG_AUTH(_reason)                                        \
do {                                                                       \
	perdition_log_auth(&auth_log, from_to_host_str, &auth, servername, \
			port, _reason, opt.ssl_mode, tls_state);           \
} while(0)

static void 
login_failed_protocol(protocol_t *protocol, int protocol_type, 
		io_t *io, token_t *tag, timed_log_t *auth_log, 
		const char *from_to_host_str, struct auth *auth,
		const char *servername, const char *port,
		const char *reason, int ssl_mode, int tls_state)
{
	sleep(PERDITION_AUTH_FAIL_SLEEP);
	if (protocol->write_str(io, NULL_FLAG, tag,
				protocol->type[protocol_type], reason) < 0) {
		VANESSA_LOGGER_DEBUG("protocol->write");
		VANESSA_LOGGER_ERR("Fatal error writing to client. "
				"Exiting child.");
		perdition_exit_cleanly(-1);
	}

	perdition_log_auth(auth_log, from_to_host_str, auth, servername, port,
			   reason, ssl_mode, tls_state);
}

void logger_init(void)
{
	vanessa_logger_t *vl;

	vl = vanessa_logger_openlog_filehandle(stderr, progname, LOG_DEBUG,
		       VANESSA_LOGGER_F_CONS|VANESSA_LOGGER_F_NO_IDENT_PID);
	if (!vl) {
		fprintf(stderr, "main: vanessa_logger_openlog_syslog\n"
			"Fatal error opening logger. Exiting.\n");
		perdition_exit_cleanly(-1);
	}

	vanessa_logger_set(vl);
}

void logger_reopen(FILE *fh)
{
	vanessa_logger_t *vl;

	if (fh != NULL)
		vl = vanessa_logger_openlog_filehandle(fh, progname,
			opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO),
			VANESSA_LOGGER_F_CONS|VANESSA_LOGGER_F_TIMESTAMP);
	else if (opt.log_facility != NULL && *(opt.log_facility) == '/')
		vl = vanessa_logger_openlog_filename(opt.log_facility,
			progname,
			opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO),
			VANESSA_LOGGER_F_CONS|VANESSA_LOGGER_F_TIMESTAMP);
	else
		vl = vanessa_logger_openlog_syslog_byname(opt.log_facility,
			progname,
			opt.debug?LOG_DEBUG:(opt.quiet?LOG_ERR:LOG_INFO),
			LOG_CONS);

	if (vl == NULL) {
    		VANESSA_LOGGER_DEBUG("vanessa_logger_openlog");
		VANESSA_LOGGER_ERR("Fatal error opening logger. Exiting.");
		perdition_exit_cleanly(-1);
	}

	vanessa_logger_closelog(vanessa_logger_get());
	vanessa_logger_set(vl);
}

#define LOGIN_FAILED_PROTOCOL(_type, _reason)                               \
do {                                                                        \
	login_failed_protocol(protocol, _type, client_io, client_tag,       \
			&auth_log, from_to_host_str, &auth, servername,     \
			port, "failed: " _reason, opt.ssl_mode, tls_state); \
} while(0)

static void perdition_log_close_early(const char *from_to_host_str,
				      struct auth *auth)
{
	struct quoted_str authorisation_id = quote_str(auth->authorisation_id);

	VANESSA_LOGGER_ERR_UNSAFE("Closing NULL session:%s "
				  "authorisation_id=%s%s%s "
				  "authentication_id=\"%s\"",
				  from_to_host_str,
				  authorisation_id.quote,
				  authorisation_id.str,
				  authorisation_id.quote,
				  str_null_safe(auth->authentication_id));
}

static void perdition_log_close(const char *from_to_host_str,
				struct auth *auth, int received, int sent)
{
	struct quoted_str authorisation_id = quote_str(auth->authorisation_id);

	VANESSA_LOGGER_ERR_UNSAFE("Closing session:%s "
				  "authorisation_id=%s%s%s "
				  "authentication_id=\"%s\" "
				  "received=%d sent=%d",
				  from_to_host_str,
				  authorisation_id.quote,
				  authorisation_id.str,
				  authorisation_id.quote,
				  str_null_safe(auth->authentication_id),
				  received, sent);
}

/**********************************************************************
 * Muriel the main function
 **********************************************************************/

int main (int argc, char **argv, char **envp){
  STRUCT_AUTH(auth);
  char *server_resp_buf = NULL;
  char *buffer;
  user_server_port_t *usp=NULL;
  protocol_t *protocol=NULL;
  token_t *our_tag=NULL;
  token_t *client_tag=NULL;
  size_t server_resp_buf_size=0;
  flag_t tls_state = 0;
  timed_log_t auth_log;
  char from_to_host_str[((NI_MAXHOST+NI_MAXSERV)*2)+2];
  char from_host_str[NI_MAXHOST];
  char to_host_str[NI_MAXHOST];
  char from_serv_str[NI_MAXSERV];
  char to_serv_str[NI_MAXSERV];
  char *servername=NULL;
  char *port=NULL;
  io_t *client_io=NULL;
  io_t *server_io=NULL;
  FILE *fh;
  size_t bytes_written = 0;
  size_t bytes_read = 0;
  int status;
  int round_robin_server=0;
  int rnd;
  int s=-1;
  int *g = NULL;
  int rc;
  int flag;

#ifdef WITH_SSL_SUPPORT
  SSL_CTX *ssl_ctx=NULL;
#endif /* WITH_SSL_SUPPORT */

  /* Create Logger */
  progname = argv[0];
  logger_init();

  /*Parse options*/
  options(argc, argv, OPT_FIRST_CALL);

  /*Read config file*/
  if(opt.config_file!=NULL){
    config_file_to_opt(opt.config_file);
  }

  /* Initialise setting of proctitle */
  init_set_proc_title(argc, argv, envp);
  progname = strdup(get_progname(argv[0]));
  if (!progname) {
	  VANESSA_LOGGER_DEBUG_ERRNO("strdup");
	  VANESSA_LOGGER_ERR("Error initialising process title\n");
	  perdition_exit_cleanly(-1);
  }
  set_proc_title("%s: daemon", progname);

  /* Update Logger */
  if (!opt.debug)
    vanessa_logger_change_max_priority(vanessa_logger_get(),
				       opt.quiet?LOG_ERR:LOG_INFO);

  /*Open the dbserver_get library, if we have a library*/
  if(getserver_openlib(opt.map_library, opt.map_library_opt,
        &handle, &dbserver_get, &dbserver_get2)<0){
    VANESSA_LOGGER_ERR_UNSAFE("dlopen of \"%s\" failed", 
    str_null_safe(opt.map_library));
    usage(-1);
    perdition_exit_cleanly(-1);
  }

  /*Set signal handlers*/
  signal(SIGHUP,    perdition_reread_handler);
  signal(SIGINT,    perdition_exit_cleanly);
  signal(SIGQUIT,   perdition_exit_cleanly);
  signal(SIGILL,    perdition_exit_cleanly);
  signal(SIGTRAP,   perdition_exit_cleanly);
  signal(SIGIOT,    perdition_exit_cleanly);
  signal(SIGBUS,    perdition_exit_cleanly);
  signal(SIGFPE,    perdition_exit_cleanly);
  signal(SIGUSR1,   vanessa_socket_handler_noop);
  signal(SIGSEGV,   perdition_exit_cleanly);
  signal(SIGUSR2,   vanessa_socket_handler_noop);
  signal(SIGPIPE,   SIG_IGN);
  signal(SIGALRM,   perdition_exit_cleanly);
  signal(SIGTERM,   perdition_exit_cleanly);
  signal(SIGCHLD,   vanessa_socket_handler_reaper);
  signal(SIGURG,    perdition_exit_cleanly);
  signal(SIGXCPU,   perdition_exit_cleanly);
  signal(SIGXFSZ,   perdition_exit_cleanly);
  signal(SIGVTALRM, perdition_exit_cleanly);
  signal(SIGPROF,   perdition_exit_cleanly);
  signal(SIGWINCH,  perdition_exit_cleanly);
  signal(SIGIO,     perdition_exit_cleanly);

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

  /*
   * Re-create logger now process is detached (unless in inetd mode)
   * and configuration file has been read.
   */
  logger_reopen(fh);

  /*Seed the uname structure*/
  if((system_uname=(struct utsname *)malloc(sizeof(struct utsname)))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc system_uname");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
    perdition_exit_cleanly(-1);
  }
  if(uname(system_uname)<0){
    VANESSA_LOGGER_DEBUG("uname");
    VANESSA_LOGGER_ERR("Fatal error finding uname for system. Exiting");
    perdition_exit_cleanly(-1);
  }

  /*Set up protocol structure*/
  if((protocol=protocol_initialise(opt.protocol, protocol))==NULL){
    VANESSA_LOGGER_DEBUG("protocol_initialise");
    VANESSA_LOGGER_ERR("Fatal error initialising protocol. Exiting.");
    perdition_exit_cleanly(-1);
  }

  /*Set listen and outgoing port now the protocol structure is accessable*/
  if((opt.listen_port=protocol->port(opt.listen_port))==NULL){
    VANESSA_LOGGER_DEBUG("protocol->port 1");
    VANESSA_LOGGER_ERR("Fatal error finding port to listen on. Exiting.");
    perdition_exit_cleanly(-1);
  }
  if((opt.outgoing_port=protocol->port(opt.outgoing_port))==NULL){
    VANESSA_LOGGER_DEBUG("protocol->port 2");
    VANESSA_LOGGER_ERR("Fatal error finding port to connect to. Exiting.");
    perdition_exit_cleanly(-1);
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
	  	perdition_exit_cleanly(-1);
  	}
  }
  else {
	  our_tag = NULL;
  }

  /*
   * Log the options we will be running with.
   * If we are in inetd mode then only do this if debugging is turned on,
   * else debugging is a bit too verbose.
   */
  if ((!opt.quiet && !opt.inetd_mode && !opt.no_daemon && !fh) || opt.debug) {
    if (log_options()) {
      VANESSA_LOGGER_DEBUG("log_options");
      VANESSA_LOGGER_ERR("Fatal error logging options. Exiting.");
      perdition_exit_cleanly(-1);
    }
  }

#ifdef WITH_SSL_SUPPORT
  /*Set up the ssl mode */
  opt.ssl_mode=protocol->encryption(opt.ssl_mode);

  if(opt.ssl_mode & SSL_LISTEN_MASK) {
    ssl_ctx = perdition_ssl_ctx(opt.ssl_ca_file, opt.ssl_ca_path,
				opt.ssl_cert_file, opt.ssl_key_file,
				opt.ssl_ca_chain_file, opt.ssl_listen_ciphers,
				PERDITION_SSL_SERVER);
    if(!ssl_ctx) {
      PERDITION_DEBUG_SSL_ERR("perdition_ssl_ctx");
      VANESSA_LOGGER_ERR("Fatal error establishing SSL context for listening");
      perdition_exit_cleanly(-1);
    }
  }
#endif /* WITH_SSL_SUPPORT */

  /* Close file descriptors and detach process from shell as necessary */
  if (opt.inetd_mode || opt.no_daemon || fh != NULL)
    vanessa_socket_daemon_inetd_process();
  else {
    vanessa_socket_daemon_process();
    if (vanessa_logger_reopen(vanessa_logger_get()) < 0) {
      fprintf(stderr, "Fatal error reopening logger. Exiting.");
      perdition_exit_cleanly(-1);
    }
  }

  /* Create PID file */
  if (!opt.inetd_mode && opt.pid_file && *opt.pid_file) {
  	if(write_pid_file(opt.pid_file, opt.username, opt.group) < 0) {
		VANESSA_LOGGER_DEBUG("write_pid_file");
		VANESSA_LOGGER_ERR("Could not write pid file");
		perdition_exit_cleanly(1);
	}
	pid_file = opt.pid_file;
  }

  /*
   * If we are using the server's ok line then allocate a buffer to store it
   */ 
  if(opt.server_resp_line){
    server_resp_buf = malloc(MAX_LINE_LENGTH);
    if (!server_resp_buf) {
      VANESSA_LOGGER_DEBUG_ERRNO("malloc server_resp_buf");
      VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
      perdition_exit_cleanly(-1);
    }
  }

  /*
   * Allocate the peername and sockname structures
   */
  sockname = malloc(sizeof(*sockname));
  if (!sockname) {
    VANESSA_LOGGER_DEBUG_ERRNO("malloc sockname");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
    perdition_exit_cleanly(-1);
  }
  peername = malloc(sizeof(*peername));
  if (!peername) {
    VANESSA_LOGGER_DEBUG_ERRNO("malloc peername");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
    perdition_exit_cleanly(-1);
  }
  

  /* Open incoming socket as required */
  if(!opt.inetd_mode) {
	  size_t nfrom;
	  const char **fromv;
	  
  	  if (opt.bind_address) 
		  nfrom = vanessa_dynamic_array_get_count(opt.bind_address);
	  else 
		  nfrom = 1;
	  
	  fromv = malloc(((nfrom * 2) + 1));
	  if (!fromv) {
		  VANESSA_LOGGER_DEBUG_ERRNO("malloc fromv");
		  VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting.");
		  perdition_exit_cleanly(-1);
	  }
	  
  	  if (opt.bind_address) {
		  size_t i;
		  user_server_port_t *from_usp;
		  for (i = 0; i < nfrom; i++) {
			  from_usp = vanessa_dynamic_array_get_element(
						opt.bind_address, i);
			  fromv[i * 2] = user_server_port_get_server(from_usp);
			  fromv[(i * 2) + 1] = user_server_port_get_port(
			  			from_usp);
			  if (!fromv[(i * 2) + 1])
				  fromv[(i * 2) + 1] = opt.listen_port;
		  }
	  }
	  else {
	  	  fromv[0] = "0.0.0.0";
	  	  fromv[1] = opt.listen_port;
	  }
	  fromv[nfrom * 2] = NULL;
	  flag = 0;
    	  if (opt.no_lookup)
	    	flag |= VANESSA_SOCKET_NO_LOOKUP;
    	  if (opt.tcp_keepalive)
	    	flag |= VANESSA_SOCKET_TCP_KEEPALIVE;
	  g = vanessa_socket_server_bindv(fromv, flag);
	  free(fromv);
	  if(!g) {
		  VANESSA_LOGGER_DEBUG("vanessa_socket_server_bindv");
		  VANESSA_LOGGER_ERR("Fatal error listening for connections."
				     "Exiting.");
		  perdition_exit_cleanly(-1);
	  }
  }

  /*
   * Become someone else
   * NB: We do this later if we are going to authenticate locally 
   */
#ifdef WITH_PAM_SUPPORT
  if(opt.authenticate_in) {
    if(geteuid()){
      VANESSA_LOGGER_INFO("Warning: not invoked as root, "
		      "local authentication may fail");
    }
  }
  else
#endif
    PERDITION_SET_UID_AND_GID;

  /* Get an incoming connection */
  if(opt.inetd_mode){
    socklen_t namelen;

    if((client_io=io_create_fd(0, 1, PERDITION_LOG_STR_CLIENT))==NULL){
      VANESSA_LOGGER_DEBUG("io_create_fd 1");
      VANESSA_LOGGER_ERR("Fatal error setting IO. Exiting.");
      perdition_exit_cleanly(-1);
    }
    io_set_timeout(client_io, opt.authenticate_timeout);

    namelen = sizeof(*peername);
    if (getpeername(0, (struct sockaddr *)peername, &namelen)) {
      free(peername);
      peername=NULL;
    }

    namelen = sizeof(*sockname);
    if (getsockname(1, (struct sockaddr *)sockname, &namelen)) {
      free(sockname);
      sockname=NULL;
    }
  }
  else{
    flag = 0;
    if (opt.tcp_keepalive)
      flag |= VANESSA_SOCKET_TCP_KEEPALIVE;
    s = vanessa_socket_server_acceptv(g, opt.connection_limit,
				      (struct sockaddr *) peername,
				      (struct sockaddr *) sockname, flag);
    if(s < 0){
      VANESSA_LOGGER_DEBUG("vanessa_socket_server_accept");
      VANESSA_LOGGER_ERR("Fatal error accepting child connection. Exiting.");
      perdition_exit_cleanly(-1);
    }

    /* Child processes don't clean up the pid file */
    pid_file = NULL;

    /* Reopen the logger, the child gets its own FDs */
    vanessa_logger_reopen(vanessa_logger_get());

    if((client_io=io_create_fd(s, s, PERDITION_LOG_STR_CLIENT))==NULL){
      VANESSA_LOGGER_DEBUG("io_create_fd 2");
      VANESSA_LOGGER_ERR("Fatal error setting IO. Exiting.");
      perdition_exit_cleanly(-1);
    }
    io_set_timeout(client_io, opt.authenticate_timeout);
  }

  /* A child process, or process handling an inetd connection
   * should exit on receipt of a SIG PIPE.
   */
  signal(SIGPIPE,   perdition_exit_cleanly);

  /* Get the source and destination ip address as a string */
  if (peername!=NULL) {
    rc = getnameinfo((struct sockaddr *)peername,
		     perdition_get_salen((struct sockaddr *)peername),
		     from_host_str, NI_MAXHOST, from_serv_str, NI_MAXSERV,
		     NI_NUMERICHOST|NI_NUMERICSERV);
    if (rc) {
        VANESSA_LOGGER_DEBUG_UNSAFE("getnameinfo peername: %s",
				    gai_strerror(rc));
	VANESSA_LOGGER_ERR("Fatal error formatting peername");
	perdition_exit_cleanly(-1);
    }
  }
  else {
    *from_host_str='\0';
    *from_serv_str='\0';
  }
  if (sockname!=NULL) {
    rc = getnameinfo((struct sockaddr *)sockname,
		     perdition_get_salen((struct sockaddr *)sockname),
		     to_host_str, NI_MAXHOST, to_serv_str, NI_MAXSERV,
		     NI_NUMERICHOST|NI_NUMERICSERV);
    if (rc) {
        VANESSA_LOGGER_DEBUG_UNSAFE("getnameinfo sockname: %s",
				    gai_strerror(rc));
	VANESSA_LOGGER_ERR("Fatal error formatting sockname");
	perdition_exit_cleanly(-1);
    }
  }
  else {
    *to_host_str='\0';
    *to_serv_str='\0';
  }
  *from_to_host_str='\0';
  if(peername!=NULL && sockname!=NULL){
    strcat(from_to_host_str, " ");
    strcat(from_to_host_str, from_host_str);
    strcat(from_to_host_str, ":");
    strcat(from_to_host_str, from_serv_str);
    strcat(from_to_host_str, "->");
    strcat(from_to_host_str, to_host_str);
    strcat(from_to_host_str, ":");
    strcat(from_to_host_str, to_serv_str);
  }

  /*Seed rand*/
  srand(time(NULL)*getpid());
  rnd=rand();

  /*Log the session and change the proctitle*/
  if(opt.inetd_mode) {
    VANESSA_LOGGER_INFO_UNSAFE("Connect: %s inetd_pid=%d",
          from_to_host_str, getppid());
  }
  else {
    VANESSA_LOGGER_INFO_UNSAFE("Connect: %s", from_to_host_str);
  }
  set_proc_title("%s: connect (%s)", progname, from_to_host_str);

#ifdef WITH_SSL_SUPPORT
  if(opt.ssl_mode & SSL_MODE_SSL_LISTEN) {
    client_io = perdition_ssl_server_connection(client_io, ssl_ctx);
    if(!client_io) {
      VANESSA_LOGGER_DEBUG("perdition_ssl_server_connection SSL");
      VANESSA_LOGGER_ERR("Fatal error establishing SSL connection to client");
      perdition_exit_cleanly(-1);
    }
  }
#endif /* WITH_SSL_SUPPORT */

  /*Speak to our client*/
  if(protocol->greeting(client_io, GREETING_ADD_NODENAME)){
    VANESSA_LOGGER_DEBUG("greeting");
    VANESSA_LOGGER_ERR_UNSAFE("Fatal error writing to client %s."
			      "Exiting child.", from_to_host_str);
    perdition_exit_cleanly(-1);
  }

  /* Authenticate the user*/
  for(;;){
    /*Read the USER and PASS lines from the client */
    status = (*(protocol->in_get_auth))(client_io, opt.ssl_mode, tls_state,
					&auth, &client_tag);
    token_flush();
    if(status<0){
      VANESSA_LOGGER_DEBUG("protocol->in_get_auth");
      if (io_get_err(client_io) == io_err_timeout)
	VANESSA_LOGGER_ERR_UNSAFE("Fatal Error: Timeout reading "
				  "authentication information from "
				  "client%s: Exiting child",
				  from_to_host_str);
      else
	VANESSA_LOGGER_ERR_UNSAFE("Fatal Error reading authentication "
				  "information from client%s: "
				  "Exiting child", from_to_host_str);
      perdition_exit_cleanly(-1);
    }
    else if(status == 1){
      perdition_log_close_early(from_to_host_str, &auth);
      perdition_exit_cleanly(0);
    }
#ifdef WITH_SSL_SUPPORT
    else if((status == 2) && (opt.ssl_mode & SSL_MODE_TLS_LISTEN)){
      /* We have received a STLS */
      client_io = perdition_ssl_server_connection(client_io, ssl_ctx);
      if(!client_io) {
        VANESSA_LOGGER_DEBUG("perdition_ssl_server_connection TLS");
	VANESSA_LOGGER_ERR("Fatal error establishing TLS connection");
        perdition_exit_cleanly(-1);
      }
      tls_state |= SSL_MODE_TLS_LISTEN;
      continue;
    }
    else if(opt.login_disabled ||
		    ((status == 0) && (opt.ssl_mode & SSL_MODE_TLS_LISTEN) &&
		    (opt.ssl_mode & SSL_MODE_TLS_LISTEN_FORCE) &&
		    !(tls_state & SSL_MODE_TLS_LISTEN))) {
	    LOGIN_FAILED_PROTOCOL(PROTOCOL_NO, "Login Disabled");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
#endif /* WITH_SSL_SUPPORT */

    {
    char *id;
    id = username_mangle(auth_get_authorisation_id(&auth), STATE_GET_SERVER);
    if (!id) {
      VANESSA_LOGGER_DEBUG("username_mangle STATE_GET_SERVER");
      VANESSA_LOGGER_ERR_UNSAFE("Fatal error manipulating username "
				"for client \"%s\": Exiting child",
				from_host_str);
      perdition_exit_cleanly(-1);
    }

    /*Read the server from the map, if we have a map*/
    if(dbserver_get || dbserver_get2 || opt.client_server_specification) {
	usp = getserver(id, from_host_str, to_host_str,
			from_serv_str, to_serv_str,
			dbserver_get, dbserver_get2);
    }

    if (id != auth_get_authorisation_id(&auth))
      free(id);
    }

    if(usp){
      port = usp->port;
      servername = usp->server;
    
      if(opt.username_from_database && usp->user){
      	char * new_id = strdup(usp->user);
        if (!new_id) {
	    VANESSA_LOGGER_DEBUG_ERRNO("strdup");
            VANESSA_LOGGER_ERR_UNSAFE("Fatal error manipulating username "
				      "for client \"%s\": Exiting child",
				      from_host_str);
        }
        free(auth_get_authorisation_id(&auth));
	auth_set_authorisation_id(&auth, new_id);
      }
    }

    /*Use the default server if we have one and the servername is not set*/
    if((!servername || !*servername || round_robin_server) && 
		    opt.outgoing_server!=NULL){
      round_robin_server=1;
      rnd=(rnd+1)%vanessa_dynamic_array_get_count(opt.outgoing_server);
      usp=vanessa_dynamic_array_get_element(opt.outgoing_server,rnd);
      servername=user_server_port_get_server(usp);
      port=user_server_port_get_port(usp);
    }

    /*Use the default port if the port is not set*/
    if(!port || !*port) {
      port=opt.outgoing_port;
    }

    /*Try again if we didn't get anything useful*/
    if(!servername || !*servername) {
	    LOGIN_FAILED_PROTOCOL(PROTOCOL_ERR, "Could not determine server");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }

#ifdef WITH_PAM_SUPPORT
    if(opt.authenticate_in){
      struct auth auth2 = auth;
      char *id;

      id = username_mangle(auth_get_authorisation_id(&auth), STATE_LOCAL_AUTH);
      if (!id) {
        VANESSA_LOGGER_DEBUG("username_mangle STATE_LOCAL_AUTH");
        VANESSA_LOGGER_ERR_UNSAFE("Fatal error manipulating username for "
				  "client \"%s\": Exiting child",
				  from_host_str);
        perdition_exit_cleanly(-1);
      }
      auth_set_authorisation_id(&auth2, id);

      status = protocol->in_authenticate(&auth2, client_io, client_tag);
      if (id != auth_get_authorisation_id(&auth))
      	free(id);
      if (!status) {
        VANESSA_LOGGER_DEBUG("protocol->in_authenticate");
        VANESSA_LOGGER_INFO(
	  "Local authentication failure for client: Allowing retry."
        );
  	PERDITION_LOG_AUTH("failed: local authentication failure");
        PERDITION_CLEAN_UP_MAIN;
        continue;
      }
      else if(status<0){
        VANESSA_LOGGER_DEBUG("pop3_in_authenticate");
        VANESSA_LOGGER_ERR(
	  "Fatal error authenticating to client locally. Exiting child."
        );
        perdition_exit_cleanly(-1);
      }

      /*
       * If local authentication is used then now is the time to
       * Become someone else
       */
       PERDITION_SET_UID_AND_GID;
    }
#endif /* WITH_PAM_SUPPORT */

    /* Talk to the real pop server for the client*/
    flag = 0;
    if (opt.no_lookup)
      flag |= VANESSA_SOCKET_NO_LOOKUP;
    if (opt.tcp_keepalive)
      flag |= VANESSA_SOCKET_TCP_KEEPALIVE;
    s = vanessa_socket_client_src_open(NULL, NULL, servername, port, flag);
    if(s < 0) {
	    VANESSA_LOGGER_DEBUG("vanessa_socket_client_open");
	    LOGIN_FAILED_PROTOCOL(PROTOCOL_ERR, "Could not connect to server");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }

    if((server_io=io_create_fd(s, s, PERDITION_LOG_STR_REAL))==NULL){
      VANESSA_LOGGER_DEBUG("io_create_fd 3");
      VANESSA_LOGGER_ERR("Fatal error setting IO. Exiting.");
      perdition_exit_cleanly(-1);
    }
    io_set_timeout(server_io, opt.authenticate_timeout);

#ifdef WITH_SSL_SUPPORT
    if(opt.ssl_mode & SSL_MODE_SSL_OUTGOING) {
      server_io=perdition_ssl_client_connection(server_io, opt.ssl_ca_file, 
		      opt.ssl_ca_path, opt.ssl_outgoing_ciphers, servername);
      if(!server_io) {
        VANESSA_LOGGER_DEBUG("perdition_ssl_connection outgoing");
        VANESSA_LOGGER_ERR("Fatal error establishing SSL connection");
        perdition_exit_cleanly(-1);
      }
    }
#endif /* WITH_SSL_SUPPORT */

    {
    struct auth auth2 = auth;
    char *id;
    int sasl_mech = 0;

    /* Authenticate the user with the pop server */
    id = username_mangle(auth_get_authorisation_id(&auth), STATE_REMOTE_LOGIN);
    if (!id) {
      VANESSA_LOGGER_DEBUG("username_mangle STATE_REMOTE_LOGIN");
      VANESSA_LOGGER_ERR_UNSAFE("Fatal error manipulating username "
				"for client \"%s\": Exiting child",
				from_host_str);
      perdition_exit_cleanly(-1);
    }
    auth_set_authorisation_id(&auth2, id);

    status = (*(protocol->out_setup))(server_io, client_io, &auth2, our_tag);
    sasl_mech = status & PROTOCOL_S_SASL_MASK;
    if(status==0){
	    quit(server_io, protocol, our_tag);
	    LOGIN_FAILED_PROTOCOL(PROTOCOL_NO, "Connection Negotiation Failure");
	    if (id != auth_get_authorisation_id(&auth))
	      free(id);
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
    else if(status<0){
      VANESSA_LOGGER_DEBUG_UNSAFE("protocol->out_setup %d", status);
      VANESSA_LOGGER_ERR("Fatal error negotiating setup. Exiting child.");
      perdition_exit_cleanly(-1);
    }

#ifdef WITH_SSL_SUPPORT
    else if((opt.ssl_mode & SSL_MODE_TLS_OUTGOING) &&
          (status & PROTOCOL_S_STARTTLS)) {
      server_io=perdition_ssl_client_connection(server_io, opt.ssl_ca_file, 
		      opt.ssl_ca_path, opt.ssl_listen_ciphers, servername);
      if(!server_io) {
        VANESSA_LOGGER_DEBUG("perdition_ssl_connection outgoing");
        VANESSA_LOGGER_ERR("Fatal error establishing SSL connection");
        perdition_exit_cleanly(-1);
      }
      tls_state |= SSL_MODE_TLS_OUTGOING;
    }
    else if((opt.ssl_mode & SSL_MODE_TLS_OUTGOING) &&
		    (opt.ssl_mode & SSL_MODE_TLS_OUTGOING_FORCE) &&
		    !(status & PROTOCOL_S_STARTTLS)) {
	    quit(server_io, protocol, our_tag);
	    LOGIN_FAILED_PROTOCOL(PROTOCOL_NO, "TLS not present");
	    if (id != auth_get_authorisation_id(&auth))
	        free(id);
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
#endif /* WITH_SSL_SUPPORT */

    if(opt.server_resp_line){
      server_resp_buf_size=MAX_LINE_LENGTH-1;
    }
    token_flush();
    status = (*(protocol->out_authenticate))(server_io, client_io, tls_state,
					     &auth2, sasl_mech, our_tag,
					     protocol, server_resp_buf,
					     &server_resp_buf_size);
    if (id != auth_get_authorisation_id(&auth))
        free(id);
    if(status==0) {
	    quit(server_io, protocol, our_tag);
            if(opt.server_resp_line){
              sleep(PERDITION_AUTH_FAIL_SLEEP);
              *(server_resp_buf+server_resp_buf_size)='\0';
              if (protocol->write_str(client_io, WRITE_STR_NO_CLLF, client_tag,
				      NULL, server_resp_buf) < 0) {
                VANESSA_LOGGER_DEBUG("protocol->write_str quit");
                VANESSA_LOGGER_ERR("Fatal error writing to client. Exiting child.");
                perdition_exit_cleanly(-1);
              }
              PERDITION_LOG_AUTH("failed: Re-Authentication Failure");
            }
            else
              LOGIN_FAILED_PROTOCOL(PROTOCOL_NO, "Re-Authentication Failure");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
    if(status==2){
	    sleep(VANESSA_LOGGER_ERR_SLEEP);
	    LOGIN_FAILED_PROTOCOL(PROTOCOL_NO, "Login Disabled");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
    if (status==3) {
	    sleep(VANESSA_LOGGER_ERR_SLEEP);
	    LOGIN_FAILED_PROTOCOL(PROTOCOL_NO, "SASL mechanism unavailable");
	    PERDITION_CLEAN_UP_MAIN;
	    continue;
    }
    else if(status<0){
      VANESSA_LOGGER_DEBUG_UNSAFE("protocol->out_authenticate %d", status);
      if (io_get_err(client_io) == io_err_timeout)
	VANESSA_LOGGER_ERR("Fatal error: Timeout authenticating user. "
			   "Exiting child.");
      else
        VANESSA_LOGGER_ERR("Fatal error authenticating user. Exiting child.");
      perdition_exit_cleanly(-1);
    }

    if(opt.server_resp_line){
      *(server_resp_buf+server_resp_buf_size)='\0';
      if (protocol->write_str(client_io, WRITE_STR_NO_CLLF, client_tag,
			      NULL, server_resp_buf) < 0) {
        VANESSA_LOGGER_DEBUG("protocol->write_str logged in, server_resp");
        VANESSA_LOGGER_ERR("Fatal error writing to client. Exiting child.");
        perdition_exit_cleanly(-1);
      }
    }
    else{
      if (protocol->write_str(client_io, NULL_FLAG, client_tag,
			      protocol->type[PROTOCOL_OK], opt.ok_line) < 0) {
        VANESSA_LOGGER_DEBUG("protocol->write_str logged in");
        VANESSA_LOGGER_ERR("Fatal error writing to client. Exiting child.");
        perdition_exit_cleanly(-1);
      }
    }
    }

    break;
  }

  PERDITION_LOG_AUTH("ok");

  if(opt.server_resp_line){
     free(server_resp_buf);
  }

  /*We need a buffer for reads and writes to the server*/
  buffer = malloc(BUFFER_SIZE);
  if (!buffer) {
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    VANESSA_LOGGER_ERR("Fatal error allocating memory. Exiting child.");
    perdition_exit_cleanly(-1);
  }

  /*Let the client talk to the real server*/
  io_set_timeout(client_io, opt.timeout);
  io_set_timeout(server_io, opt.timeout);
  if(io_pipe(server_io, client_io, buffer, BUFFER_SIZE,
        &bytes_written, &bytes_read, &auth_log)<0){
    if (io_get_err(client_io) == io_err_timeout) {
      VANESSA_LOGGER_INFO("Timeout piping data.");
      if (protocol->bye && protocol->bye(client_io, "Timeout") < 0) {
        VANESSA_LOGGER_DEBUG("protocol->bye timeout");
        VANESSA_LOGGER_ERR("Fatal error writing to client. Exiting child.");
        perdition_exit_cleanly(-1);
      }
    } else {
      VANESSA_LOGGER_DEBUG("vanessa_socket_pipe");
      VANESSA_LOGGER_ERR("Fatal error piping data. Exiting child.");
      perdition_exit_cleanly(-1);
    }
  }

  /*Time to leave*/
  perdition_log_close(from_to_host_str, &auth, bytes_read, bytes_written);
  set_proc_title("%s: close (%s)", progname,
		 str_null_safe(auth_get_authorisation_id(&auth)));

  getserver_closelib(handle);
  perdition_exit_cleanly(0);

  /*Here so compilers won't barf*/
  return(0);
}


/**********************************************************************
 * perdition_reread_handler
 * A signal handler that closes and opens the map library,
 * reinitialising as necessary.
 * pre: sig: signal received by the process
 * post: signal handler reset for signal
 *       map library closed and opened
 *       This may cause shutdown and initialisation of map to
 *       take place if appropriate symbols are defined in
 *       the library. See getserver.c for details.
 **********************************************************************/

static void perdition_reread_handler(int sig){
  if(vanessa_logger_reopen(vanessa_logger_get()) < 0) {
    fprintf(stderr, "Fatal error reopening logger. Exiting.");
    perdition_exit_cleanly(-1);
  }
  VANESSA_LOGGER_INFO("Reopened logger");

  VANESSA_LOGGER_INFO_UNSAFE("Reloading map library \"%s\" with options \"%s\"",
    opt.map_library, opt.map_library_opt);
  getserver_closelib(handle);
  if(
    opt.map_library!=NULL && 
    getserver_openlib(
      opt.map_library, 
      opt.map_library_opt, 
      &handle, 
      &dbserver_get,
      &dbserver_get2
    )<0
  ){
    VANESSA_LOGGER_DEBUG("getserver_openlib");
    VANESSA_LOGGER_ERR_UNSAFE("Fatal error reopening: %s. Exiting child.", 
      opt.map_library);
    perdition_exit_cleanly(-1);
  }

  signal(sig, (void(*)(int))perdition_reread_handler);
}


/**********************************************************************
 * perdition_exit_cleanly
 * Exit perdition, cleaning up as necessary
 * pre: sig: signal received by the process
 * post: pid file is removed
 *       process exits
 **********************************************************************/

static void 
perdition_exit_cleanly(int i) 
{
     	if (pid_file && (unlink(opt.pid_file) < 0)) {
		VANESSA_LOGGER_INFO_UNSAFE("Could not remove pid file "
				"[%s]: %s\n", opt.pid_file,
				 strerror(errno));
	}
	vanessa_socket_daemon_exit_cleanly(i);
}


/* XXX: Should be in libvanessa_socket */
static int 
perdition_chown(const char *path, const char *username, const char *group)
{
	uid_t uid;
	gid_t gid;
	struct passwd *pw;
	struct group *gr;
	
	if (vanessa_socket_str_is_digit(group)) {
		gid = (gid_t) atoi(group);
	} else {
		if ((gr = getgrnam(group)) == NULL) {
			switch (errno) {
			case 0:
			case ENOENT:
			case ESRCH:
			case EBADF:
			case EPERM:
				VANESSA_LOGGER_DEBUG_UNSAFE("getgrnam: "
							    "\"%s\": "
							    "not found",
							    group);
				break;
			default:
				VANESSA_LOGGER_DEBUG_UNSAFE("getgrnam: "
							    "\"%s\": %s",
							    group,
							    strerror(errno));
				break;
			}
			return (-1);
		}
		gid = gr->gr_gid;
		/*free(gr); */
	}
	
	if (setgid(gid)) {
		VANESSA_LOGGER_DEBUG_ERRNO("setgid");
		return (-1);
	}
	
	if (vanessa_socket_str_is_digit(username)) {
		uid = (uid_t) atoi(username);
	} else {
		if ((pw = getpwnam(username)) == NULL) {
			VANESSA_LOGGER_DEBUG_ERRNO("getpwnam");
			return (-1);
		}
		uid = pw->pw_uid;
		/*free(pw); */
	}

	if(chown(path, uid, gid) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("chown");
		return -1;
	}
	
	return (0);
}


int
create_pid_directory(const char *pidfilename, const char *username,
		const char *group)  
{
	int	status;
	struct stat stat_buf;
	char    *pidfilename_cpy;
	char    *dir;

	pidfilename_cpy = strdup(pidfilename);
	if (!pidfilename_cpy) {
		VANESSA_LOGGER_DEBUG_ERRNO("strdup");
		return -1;
	}

	dir = dirname(pidfilename_cpy);

	status = stat(dir, &stat_buf); 

	if (status < 0 && errno != ENOENT && errno != ENOTDIR) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Could not stat pid-file "
				"directory [%s]: %s", dir, strerror(errno));
		free(pidfilename_cpy);
		return -1;
	}
	
	if (!status) {
		if (S_ISDIR(stat_buf.st_mode)) {
			return 0;
		}
		VANESSA_LOGGER_DEBUG_UNSAFE("Pid-File directory exists but is "
				"not a directory [%s]", dir);
		free(pidfilename_cpy);
		return -1;
        }

	if (mkdir(dir, S_IRUSR|S_IWUSR|S_IXUSR | S_IRGRP|S_IWGRP|S_IXGRP) < 0) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Could not create pid-file "
				"directory [%s]: %s", dir, strerror(errno));
		free(pidfilename_cpy);
		return -1;
	}

	if (!geteuid() &&  perdition_chown(dir, username, group) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_chown");
		free(pidfilename_cpy);
		return -1;
	}

	free(pidfilename_cpy);

	return 0;
}


int
write_pid_file(const char *pidfilename, const char *username,
		const char *group)  
{

	int     pidfilefd;
	char    pidbuf[11];
	pid_t   pid;
	ssize_t  bytes;

	if (create_pid_directory(pidfilename, username, group) < 0) {
		return -1;
	}

	while (1) {
		pidfilefd = open(pidfilename, O_CREAT|O_EXCL|O_RDWR, 
				S_IRUSR|S_IWUSR);
		if (pidfilefd < 0) {
			if (errno != EEXIST) { /* Old PID file */
				VANESSA_LOGGER_DEBUG_UNSAFE(
						"Could not open pid-file "
						"[%s]: %s", pidfilename, 
						strerror(errno));
				return -1;
			}
		}
		else {
			break;
		}

		pidfilefd = open(pidfilename, O_RDONLY, S_IRUSR|S_IWUSR);
		if (pidfilefd < 0) {
			VANESSA_LOGGER_DEBUG_UNSAFE("Could not open pid-file " 
					"[%s]: %s", pidfilename, 
					strerror(errno));
			return -1;
		}

		while (1) {
			bytes = read(pidfilefd, pidbuf, sizeof(pidbuf)-1);
			if (bytes < 0) {
				if (errno == EINTR) {
					continue;
				}
				VANESSA_LOGGER_DEBUG_UNSAFE(
						"Could not read pid-file " 
						"[%s]: %s", pidfilename, 
						strerror(errno));
				close(pidfilefd);
				return -1;
			}
			pidbuf[bytes] = '\0';
			break;
		}

		close(pidfilefd);

		if (!bytes) {
			VANESSA_LOGGER_DEBUG_UNSAFE("Invalid pid in pid-file "
	 				"[%s]: %s", pidfilename, 
					strerror(errno));
			return -1;
		}

		pid = strtol(pidbuf, NULL, 10);
		if (pid == LONG_MAX && errno == ERANGE) {
			VANESSA_LOGGER_DEBUG_UNSAFE("Invalid pid in pid-file "
	 				"[%s]: %s", pidfilename, 
					strerror(errno));
			return -1;
		}

		if (!kill(pid, 0)) {
			VANESSA_LOGGER_ERR_UNSAFE("Fatal error: "
					"Pid file [%s] exists for "
					"process [%u] which appears to be "
					"running, exiting", pidfilename, pid);
			return -1;
		}
		else if (errno != ESRCH) {
			VANESSA_LOGGER_DEBUG_UNSAFE("Error signaling old "
					"process [%u] from pid-file [%s]: %s",
					pid, pidfilename, strerror(errno));
			return -1;
		}

		if(unlink(pidfilename) < 0) {
			VANESSA_LOGGER_DEBUG_UNSAFE("Could not delete "
					"pid-file [%s]: %s", pidfilename, 
					strerror(errno));
			return -1;
		}
		VANESSA_LOGGER_INFO_UNSAFE("Removed stale pid-file [%s]", 
				pidfilename);
	}

	if (!geteuid() &&  perdition_chown(pidfilename, username, group) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_chown");
		goto unlink;
	}

	if (chmod(pidfilename, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("chmod");
		goto unlink;
	}

	if (snprintf(pidbuf, sizeof(pidbuf), "%u", 
				getpid()) >= (int)sizeof(pidbuf)) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Pid too long for buffer [%u]", 
				getpid());
		goto unlink;
	}

	while (1) {
		bytes = write(pidfilefd, pidbuf, strlen(pidbuf));
		if (bytes != (ssize_t)strlen(pidbuf)) {
			if (bytes < 0 && errno == EINTR) {
				continue;
			}
			VANESSA_LOGGER_DEBUG_UNSAFE("Could not write pid-file "
					"[%s]: %s", pidfilename,
					strerror(errno));
			goto unlink;
		}
		break;
	}

	close(pidfilefd);

	return 0;

unlink:
	close(pidfilefd);
	if(unlink(pidfilename) < 0)
		VANESSA_LOGGER_DEBUG_ERRNO("unlink");
	return -1;
}
