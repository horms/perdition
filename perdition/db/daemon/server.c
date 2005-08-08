
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vanessa_logger.h>
#include <signal.h>

#include "lib/packet.h"
#include "lib/unix_socket.h"

#define STR_LEN 108
#define BUF_LEN 1024
#define SOCK_BASE "map"

static int leaving = 0;

static void
exit_handler(int sig) 
{
	leaving++;
}


static int 
set_signal(int signum, void (*handler)(int))
{
	struct sigaction sig;

	memset(&sig, 0, sizeof(struct sigaction));
	sig.sa_handler = handler;
	return(sigaction(signum, &sig, NULL));
}


static void 
daemon_usage(int exit_status)
{
	fprintf(exit_status?stderr:stdout,
			"perdition test-server version %s Copyright Horms\n"
			"\n"
			"Used sample perdition map daemon\n"
			"Always responds with \"response\" as the server\n"
			"\n"
			"Usage: test-server [socket] response\n"
			"       test-server -h\n"
			"       test-server --help\n"
			"  Where:\n"
			"    socket: unix domain socket to use.\n"
			"    (default \"%s\")\n"
			"    -h|--help: show this text.\n"
			,
			VERSION, PERDITION_UN_SERVER_SOCKET);
	exit(exit_status);
}


int
main(int argc, char **argv)
{
	perdition_un_t un;
	struct sockaddr_un unaddr;
	int bytes_recv;
	int bytes_sent;
	socklen_t socklen;
	vanessa_logger_t *vl;
	perdition_packet_t *req_packet;
	perdition_packet_t *rsp_packet;
	perdition_packet_str_t user;
	perdition_packet_str_t server;
	char *server_socket = NULL;
	char *response = NULL;

	vl = vanessa_logger_openlog_filehandle(stderr, "test-server",
			LOG_DEBUG, 0);
	vanessa_logger_set(vl);

	if(argc == 2) {
		server_socket = PERDITION_UN_SERVER_SOCKET;
		response = argv[1];
	}
	else if(argc == 3) {
		server_socket = argv[1];
		response = argv[2];
	}
	else {
		daemon_usage(-1);
	}

	if(!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		daemon_usage(0);
	}

	set_signal(SIGHUP,  SIG_IGN);
	set_signal(SIGINT, exit_handler);
	set_signal(SIGQUIT, exit_handler);
	set_signal(SIGILL, exit_handler);
	set_signal(SIGTRAP, exit_handler);
	set_signal(SIGABRT, exit_handler);
	set_signal(SIGBUS, exit_handler);
	set_signal(SIGFPE, exit_handler);
	set_signal(SIGUSR1, SIG_IGN);
	set_signal(SIGSEGV, exit_handler);
	set_signal(SIGUSR2, SIG_IGN);
	set_signal(SIGPIPE, SIG_IGN);
	set_signal(SIGTERM, exit_handler);

	perdition_un_init(&un);

	req_packet = perdition_packet_create();
	if(req_packet < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_create");
		goto leave;
	}

	rsp_packet = perdition_packet_create();
	if(rsp_packet < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_create");
		goto leave;
	}

	strncpy(un.name, server_socket, PERDITION_UN_STR_LEN-1);
	un.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (un.fd < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("socket");
		goto leave;
	}

	memset(&unaddr, 0, sizeof(struct sockaddr_un));
	unaddr.sun_family = AF_UNIX;
	strncpy(unaddr.sun_path, un.name, sizeof(struct sockaddr_un));

	unlink(unaddr.sun_path);
	if(bind(un.fd, (struct sockaddr *) &unaddr, 
				sizeof(struct sockaddr_un)) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("bind");
		goto leave;
	}

	while(!leaving) {
		socklen = sizeof(struct sockaddr_un);
		memset(&unaddr, 0, socklen);
		bytes_recv = recvfrom(un.fd, req_packet, 
				PERDITION_PACKET_MAX_PACKET_LEN, 0, 
				(struct sockaddr *) &unaddr, &socklen);
		if(bytes_recv == 0) {
			continue;
		}
		if(bytes_recv < 0) {
			if(errno == EINTR) {
				continue;
			}
			VANESSA_LOGGER_DEBUG_ERRNO("recvfrom");
			goto leave;
		}

		VANESSA_LOGGER_DEBUG_UNSAFE("%d bytes recieved from %s", 
				bytes_recv, unaddr.sun_path);

		if(perdition_packet_verify_v1_req(req_packet, bytes_recv, 
					&user, NULL) < 0) {
			VANESSA_LOGGER_DEBUG("perdition_packet_verify_v1_req");
			continue;
		}

		PERDITION_PACKET_STR_PACK(server, response);
		if(perdition_packet_init_v1_rsp(&rsp_packet, 0,
				&user, &server, NULL) < 0) {
			VANESSA_LOGGER_DEBUG("perdition_packet_init_v1_req");
			continue;
		}

		while (!leaving) {
			bytes_sent = sendto(un.fd, rsp_packet, 
					ntohs(rsp_packet->head.length), 0, 
					(struct sockaddr *) &unaddr, socklen);
			if(bytes_sent < 0) {
				if(errno == EINTR) {
					continue;
				}
				if(errno == ENOENT || errno == ECONNREFUSED) {
					break;
				}
				VANESSA_LOGGER_DEBUG_ERRNO("sendto");
				goto leave;
			}
			/* Don't care, client should retry */
			/*
			if(bytes_sent != bytes_recv) { ; }
			*/
			break;
		}
	}

leave:
	perdition_un_close(&un);
	return(0);
}
