
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vanessa_logger.h>

#include "packet.h"
#include "unix_socket.h"

#define BUF_LEN 1024
#define DIR_TEMPLATE "/tmp/perdition-map-XXXXXX"
/* #define SERVER_SOCKET "/var/run/perdition.db" */
#define SOCK_BASE "map"

#define TIMEOUT 1
#define MAX_RETRY 5 


static struct sockaddr_in *peername = NULL;
static struct sockaddr_in *sockname = NULL;

static void 
usage(int exit_status)
{
	fprintf(exit_status?stderr:stdout,
			"perdition test-client version %s Copyright Horms\n"
			"\n"
			"Used to test a perdition map daemon\n"
			"\n"
			"Usage: test-client [socket] key\n"
			"       test-client -h\n"
			"       test-client --help\n"
			"  Where:\n"
			"    key: key to look up in the database.\n"
			"    socket: unix domain socket of server.\n"
			"    (default \"%s\")\n"
			"    -h|--help: show this text.\n"
			,
			VERSION, PERDITION_UN_SERVER_SOCKET);
	exit(exit_status);
}


int
main(int argc, char **argv)
{
	perdition_un_t sock;
	perdition_un_t peer;
	struct sockaddr_un unaddr;
	int bytes;
	vanessa_logger_t *vl;
	perdition_packet_t *packet;
	perdition_packet_str_t key;
	perdition_packet_str_t domain_delimiter;
	perdition_packet_str_t user;
	perdition_packet_str_t server;
	perdition_packet_str_t port;
	char *server_socket;
	char *query;
	int status = -1;

	vl = vanessa_logger_openlog_filehandle(stderr, "test-client",
			LOG_DEBUG, 0);
	vanessa_logger_set(vl);

	if(argc == 2) {
		server_socket = PERDITION_UN_SERVER_SOCKET;
		query = argv[1];
	}
	else if(argc == 3) {
		server_socket = argv[1];
		query = argv[2];
	}
	else {
		usage(-1);
	}

	if(!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		usage(0);
	}

	packet = perdition_packet_create();
	if(!packet) {
		VANESSA_LOGGER_DEBUG("perdition_packet_create");
		goto leave;
	}

	PERDITION_PACKET_STR_PACK(key, query);
	PERDITION_PACKET_STR_PACK(domain_delimiter, "@");

	if(perdition_packet_init_v1_req(&packet, 0,
			peername?peername->sin_addr.s_addr:0UL,
			peername?peername->sin_port:0U,
			sockname?sockname->sin_addr.s_addr:0UL, 
			sockname?sockname->sin_port:0U, 
			&key, &domain_delimiter) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_init_v1");
		goto leave;
	}

	perdition_un_init(&sock);

	memcpy(sock.dir, DIR_TEMPLATE, PERDITION_UN_STR_LEN-1);
	if(!mkdtemp(sock.dir)) {
		VANESSA_LOGGER_DEBUG_ERRNO("mkdtemp");
		return (-1);
	}
	snprintf(sock.name, PERDITION_UN_STR_LEN-1, "%s/%s.%d", 
			sock.dir, SOCK_BASE, getpid());

	sock.fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (peer.fd < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("socket");
		goto leave;
	}

	memset(&unaddr, 0, sizeof(struct sockaddr_un));
	unaddr.sun_family = AF_UNIX;
	strncpy(unaddr.sun_path, sock.name, sizeof(struct sockaddr_un));

	if(bind(sock.fd, (struct sockaddr *) &unaddr, 
				sizeof(struct sockaddr_un)) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("bind");
		goto leave;
	}

	perdition_un_init(&peer);
	strncpy(peer.name, server_socket, PERDITION_UN_STR_LEN-1);

	bytes = perdition_un_send_recv(&sock, &peer, (void *)packet, 
			ntohs(packet->head.length),
			PERDITION_PACKET_MAX_PACKET_LEN, TIMEOUT, MAX_RETRY);
	if(bytes < 0) {
		VANESSA_LOGGER_DEBUG("send_recv_packet");
		goto leave;
	}

	if(perdition_packet_verify_v1_rsp(packet, bytes,
				&user, &server, &port) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_packet_verify_v1_req");
		goto leave;
	}

	write(1, "user=\"", 6);
	if(user.length) {
		write(1, user.data, user.length);
	}
	write(1, "\"\n", 2);

	write(1, "server=\"", 8);
	if(server.length) {
		write(1, server.data, server.length);
	}
	write(1, "\"\n", 2);

	write(1, "port=\"", 6);
	if(port.length) {
		write(1, port.data, port.length);
	}
	write(1, "\"\n", 2);

	status = 0;
leave:
	perdition_packet_destroy(packet);
	perdition_un_close(&sock);
	return status;
}
