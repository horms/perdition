/**********************************************************************
 * ssl.c                                                  November 2001
 * Horms                                             horms@verge.net.au
 *
 * SSL routines
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

#ifdef WITH_SSL_SUPPORT

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>

#include "ssl.h"
#include "log.h"
#include "io.h"
#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#define PERDITION_SSL_CLIENT (flag_t) 0x1
#define PERDITION_SSL_SERVER (flag_t) 0x2

static int __perdition_ssl_passwd_cb(char *buf, int size, int rwflag, 
		void *data)
{
	ssize_t nbytes;
	struct termios new;
	struct termios old;

	/* Turn echoing off */
	if(tcgetattr(0, &old) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("tcgetattr");
		return(-1);
	}
	new = old;
	new.c_lflag &= (~ECHO);
	if(tcsetattr(0, TCSANOW, &new) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("tcsetattr");
		return(-1);
	}

	/* Read Bytes */
	nbytes = read(1, buf, size-1);

	/* Turn echoing on */
	if(tcsetattr(0, TCSANOW, &old) < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("tcgetattr");
		return(-1);
	}

	if(nbytes < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("read");
		return(-1);
	}

	/* Make sure the result is null terminated */
	*(buf + nbytes) = '\0';

	/* Cut of trailing "\n" or trailing "\r\n" */
	if(nbytes > 1 && *(buf + nbytes - 1) == '\n') {
		nbytes--;
		 *(buf + nbytes) = '\0';
		if(nbytes > 1 && *(buf + nbytes - 1) == '\r') {
			nbytes--;
		 	*(buf + nbytes) = '\0';
		}
	}

	return(nbytes);
}


/**********************************************************************
 * perdition_ssl_ctx
 * Create an SSL context
 * pre: ca: certificat authorities to use. May be NULL or ""
 *      cert: certificate to use. May be NULL if privkey is NULL. 
 *            Should the path to a PEM file if non-NULL and the
 *            first item in the PEM file will be used as the 
 *            certificate.
 *      privkey: private key to use May be NULL if cert is NULL. 
 *               Should the path to a PEM file if non-NULL and the
 *               first item in the PEM file will be used as the 
 *               private key.
 *      ciphers: cipher list to use as per ciphers(1). 
 *               May be NULL in which case openssl's default is used.
 * post: If SSL is initiated and a context is created
 *       If cert is non-NULL then this certificate file is loaded
 *       If privkey is non-NULL then this private key file is loaded
 *       If cert and privkey are non-NULL then check private key
 *       against certificate.
 *       Note: If either cert of privkey are non-NULL then both must
 *       be non-NULL.
 **********************************************************************/

SSL_CTX *perdition_ssl_ctx(const char *ca, const char *cert, 
		const char *privkey, const char *ciphers)
{
	SSL_METHOD *ssl_method;
	SSL_CTX *ssl_ctx;

	/* 
	 * If either the certificate or private key is non-NULL the
	 * other should be too
	 */
	if (cert == NULL && privkey != NULL) {
		VANESSA_LOGGER_DEBUG("Certificate is NULL but "
				"private key is non-NULL");
		return (NULL);
	}

	if (privkey == NULL && cert != NULL) {
		VANESSA_LOGGER_DEBUG ("Private key is NULL but "
				"certificate is non-NULL");
		return (NULL);
	}

	/*
	 * Initialise an SSL context
	 */
	SSLeay_add_ssl_algorithms();
	ssl_method = SSLv23_method();
	SSL_load_error_strings();

	if ((ssl_ctx = SSL_CTX_new(ssl_method)) == NULL) {
		VANESSA_LOGGER_DEBUG_SSL_ERR("SSL_CTX_new");
		return (NULL);
	}

	/*
	 * Set the available ciphers
	 */
	if(ciphers && SSL_CTX_set_cipher_list(ssl_ctx, ciphers) < 0) {
		VANESSA_LOGGER_DEBUG_UNSAFE(
				"Cipher string supplied (%s) "
				"results in no available ciphers",
				ciphers);
	}

	/*
	 * Load and check the certificate and private key
	 */
	if (cert && SSL_CTX_use_certificate_file(ssl_ctx, cert, 
			SSL_FILETYPE_PEM) <= 0) {
		VANESSA_LOGGER_DEBUG_SSL_ERR_UNSAFE
		    ("SSL_CTX_use_certificate_file: \"%s\"", cert);
		VANESSA_LOGGER_ERR_UNSAFE
		    ("Error loading certificate file \"%s\"", cert);
		SSL_CTX_free(ssl_ctx);
		return (NULL);
	}

	SSL_CTX_set_default_passwd_cb(ssl_ctx, __perdition_ssl_passwd_cb);
	if (cert && SSL_CTX_use_PrivateKey_file(ssl_ctx, privkey, 
			SSL_FILETYPE_PEM) <= 0) {
		VANESSA_LOGGER_DEBUG_SSL_ERR_UNSAFE
		    ("SSL_CTX_use_PrivateKey_file: \"%s\"", privkey);
		VANESSA_LOGGER_ERR_UNSAFE
		    ("Error loading pricvate key file \"%s\"", privkey);
		SSL_CTX_free(ssl_ctx);
		return (NULL);
	}

	if(!ca || !*ca) {
		return (ssl_ctx);
	}

	/* 
	 * Load the Certificat Authorities 
	 */
	if(!(SSL_CTX_load_verify_locations(ssl_ctx, ca, 0))) {
		VANESSA_LOGGER_DEBUG_SSL_ERR_UNSAFE
		    ("SSL_CTX_load_verify_locations: \"%s\"", ca);
		VANESSA_LOGGER_ERR_UNSAFE
		    ("Error loading certificate authority file \"%s\"", ca);
		SSL_CTX_free(ssl_ctx);
		return (NULL);
	}
	SSL_CTX_set_verify_depth(ssl_ctx, 0);

	/* NB: We do not need to call SSL_CTX_check_private_key()
	 * because SSL_CTX_set_verify_depth has been called */

	return (ssl_ctx);
}


/**********************************************************************
 * __perdition_ssl_check_common_name
 * Log the details of a certificate
 * pre: cert: server certificate to check the common name of
 *      server: server name to match against the common name
 * post: none
 * return: 0 on success
 *         -1 on error
 *         -2 if the common name did not match, or the cert did
 *            not exist
 **********************************************************************/

static int __perdition_ssl_check_common_name(X509 *cert, const char *server)
{
	char *domain;
	char common_name[MAX_LINE_LENGTH];

	extern options_t opt;

	if(opt.ssl_no_cn_verify || !server) {
		return(0);
	}

	if(!cert) {
		VANESSA_LOGGER_DEBUG("no server certificate");
		return(-2);
	}
	
	if(X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), 
			NID_commonName, common_name, MAX_LINE_LENGTH) < 0) {
		VANESSA_LOGGER_DEBUG_SSL_ERR("X509_NAME_get_text_by_OBJ");
		return(-1);
	}
	common_name[MAX_LINE_LENGTH -1] = '\0';

	if(!strcmp(server, common_name)) {
		return(0);
	}
	/* A wild card common name is allowed 
	 * It should be of the form *.domain */
	if(*common_name == '*' && *(common_name+1) == '.') {
		domain = strchr(server, '.');
		if(domain && !strcmp(common_name+2, domain+1)) {
			return(0);
		}
	}

	VANESSA_LOGGER_ERR("common name missmatch");
	return(-2);
}


/**********************************************************************
 * __perdition_ssl_check_certificate
 * Log the details of a certificate
 * pre: ssl: SSL object to log
 *      cert: certificate to log
 * post: details of cerfificate are loged, if there is one
 * return: 0 on success, including if there was nothing to do
 *         -1 on error
 **********************************************************************/


static int __perdition_ssl_log_certificate(SSL *ssl, X509 *cert)
{
	char *str = NULL;

	extern options_t opt;

	if(!opt.debug) {
		return(0);
	}

	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("SSL connection using %s",
				    SSL_get_cipher(ssl));

	if (!cert) {
		return(0);
	}

	str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	if (!str) {
		VANESSA_LOGGER_DEBUG_SSL_ERR("X509_NAME_oneline");
		return(1);
	}
	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("subject: %s", str);
	free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	if (!str) {
		VANESSA_LOGGER_DEBUG_SSL_ERR("X509_NAME_oneline");
		return(-1);
	}
	VANESSA_LOGGER_DEBUG_RAW_UNSAFE("issuer: %s", str);

	free(str);
	return(0);
}


/**********************************************************************
 * __perdition_ssl_check_certificate
 * Check the details of a certificate
 * pre: io: connectoion to check certificate of
 *      ca: certificate authority file. Used to verify the server's
 *          certificate. May be NULL or ""
 *      server: server to match the common name of
 * post: details of cerfificate are loged, if there is one
 *       common name of the certificate is verified
 * return: 0 on success, including if there was nothing to do
 *         -1 on error
 *         -2 if common name mismatched server
 *         -3 if certificate was not verified
 **********************************************************************/


static int __perdition_ssl_check_certificate(io_t * io, const char *ca,
		const char *server)
{
	X509 *cert = NULL;
	SSL *ssl;
	int status = 0;

	ssl = io_get_ssl(io);
	if (!ssl) {
		VANESSA_LOGGER_DEBUG("vanessa_socket_get_ssl");
		status = -1;
		goto leave;
	}
	cert = SSL_get_peer_certificate(ssl);

	status = __perdition_ssl_log_certificate(ssl, cert);
	if(status < 0) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_log_certificate");
		goto leave;
	}

	if(ca && *ca && SSL_get_verify_result(ssl) != X509_V_OK) {
		VANESSA_LOGGER_ERR("Certificate was not verified");
		VANESSA_LOGGER_DEBUG_SSL_ERR("SSL_get_verify_result");
		status = -3;
		goto leave;
	}

	status = __perdition_ssl_check_common_name(cert, server);
	if(status < 0) {
		VANESSA_LOGGER_DEBUG("__perdition_ssl_check_common_name");
		goto leave;
	}

leave:
	if(cert) {
		X509_free(cert);
	}

	return (status);
}


/**********************************************************************
 * __perdition_ssl_connection
 * Change a stdio bassed connection into an SSL connection
 * pre: io: io_t to change
 *      ssl_ctx: SSL Context to use
 *      flag: If PERDITION_SSL_CLIENT the io is a client that has 
 *            connected to a server and SSL_connect() will be called. 
 *            If PERDITION_SSL_SERVER then the io is a server that 
 *            has accepted a connection and SSL_accept will be called.
 *            There are no other valid values for flag.
 * post: io_t has an ssl object associated with it and SSL is intiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

static io_t *__perdition_ssl_connection(io_t *io, SSL_CTX *ssl_ctx, 
		flag_t flag)
{
	io_t *new_io = NULL;
	SSL *ssl = NULL;
	int ret;

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		VANESSA_LOGGER_DEBUG_SSL_ERR("SSL_new");
		goto bail;
	}

	/* Set up io object that will use SSL */
	new_io = io_create_ssl(ssl, io_get_rfd(io), io_get_wfd(io),
			  io_get_name(io));
	if (!new_io) {
		VANESSA_LOGGER_DEBUG("io_create_ssl");
		goto bail;
	}

	io_destroy(io);
	io = NULL;

	/* Get for TLS/SSL handshake */
	if (flag & PERDITION_SSL_CLIENT) {
		SSL_set_connect_state(ssl);
		ret = SSL_connect(ssl);
		if (ret <= 0) {
			VANESSA_LOGGER_DEBUG_SSL_IO_ERR("SSL_connect",
					io_get_ssl(new_io), ret);
			goto bail;
		}
	} else {
		SSL_set_accept_state(ssl);
		ret = SSL_accept(ssl);
		if (ret <= 0) {
			VANESSA_LOGGER_DEBUG_SSL_IO_ERR("SSL_accept",
					io_get_ssl(new_io), ret);
			VANESSA_LOGGER_DEBUG("no shared ciphers?");
			goto bail;
		}
	}

	return (new_io);

      bail:
	if (new_io) {
		io_close(new_io);
		io_destroy(new_io);
	} else if(ssl) {
		SSL_free(ssl);
	}
	if (io) {
		io_destroy(io);
	}
	return (NULL);
}


/**********************************************************************
 * perdition_ssl_client_connection
 * Change a stdio bassed connection to a remote server, into an SSL 
 * connection.
 * pre: io: io_t to change. A client that has connected to a server, 
 *          SSL_connect() will be called.
 *      ca: Certificate authority file. May be NULL or ""
 *          Used to verify the server's certificate
 *      ciphers: cipher list to use as per ciphers(1). 
 *               May be NULL in which case openssl's default is used.
 *      server: server name to verify with the common name in
 *              the server's certificate
 * post: io_t has an ssl object associated with it and SSL is intiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *perdition_ssl_client_connection(io_t * io, const char *ca,
		const char *ciphers, const char *server)
{
	SSL_CTX *ssl_ctx;
	io_t *new_io;

	ssl_ctx = perdition_ssl_ctx(ca, NULL, NULL, ciphers);
	if (!ssl_ctx) {
		VANESSA_LOGGER_DEBUG_SSL_ERR("perdition_ssl_ctx");
		io_destroy(io);
		return(NULL);
	}

	new_io = __perdition_ssl_connection(io, ssl_ctx, PERDITION_SSL_CLIENT);
	if (!new_io) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_connection");
		return(NULL);
	}

	if (__perdition_ssl_check_certificate(new_io, ca, server) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_check_certificate");
		io_destroy(new_io);
		return(NULL);
	}

	return(new_io);
}


/**********************************************************************
 * perdition_ssl_server_connection
 * Change a stdio bassed connection that receives client connections,
 * into an SSL connection
 * pre: io: io_t to change
 *      ssl_ctx: SSL Context to use
 * post: io_t has an ssl object associated with it and SSL is intiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *perdition_ssl_server_connection(io_t * io, SSL_CTX * ssl_ctx)
{
	io_t *new_io;

	new_io = __perdition_ssl_connection(io, ssl_ctx, PERDITION_SSL_SERVER);
	if (!new_io) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_connection");
		return (NULL);
	}

	if (__perdition_ssl_check_certificate(new_io, NULL, NULL) < 0) {
		VANESSA_LOGGER_DEBUG("perdition_ssl_check_certificate");
		io_destroy(new_io);
		return(NULL);
	}

	return (new_io);
}

#endif				/* WITH_SSL_SUPPORT */
