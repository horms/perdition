/**********************************************************************
 * ssl.h                                                  November 2001
 * Horms                                             horms@vergenet.net
 *
 * SSL routines
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2002  Horms
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

#ifndef _PERDITION_SSL_H
#define _PERDITION_SSL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WITH_SSL_SUPPORT

#include "io.h"
#include "perdition_types.h"


/**********************************************************************
 * perdition_ssl_ctx
 * Create an SSL context
 * pre: ca: certificat authorities to use. May be NULL
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
		const char *privkey, const char *ciphers);


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
		const char *ciphers, const char *server);


/**********************************************************************
 * perdition_ssl_server_connection
 * Change a stdio bassed connection that revieves client connections,
 * into an SSL connection
 * io: io_t to change
 * ssl_ctx: SSL Context to use
 * post: io_t has an ssl object associated with it and SSL is intiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *perdition_ssl_server_connection(io_t * io, SSL_CTX * ssl_ctx);

#endif				/* WITH_SSL_SUPPORT */

#endif 				/* _PERDITION_SSL_H */
