/**********************************************************************
 * ssl.h                                                  November 2001
 * Horms                                             horms@verge.net.au
 *
 * SSL routines
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2004  Horms
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
 * pre: ca_file: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      ca_path: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      cert: certificate to use. May be NULL if privkey is NULL. 
 *            Should the path to a PEM file if non-NULL and the
 *            first item in the PEM file will be used as the 
 *            certificate.
 *      privkey: private key to use May be NULL if cert is NULL. 
 *               Should the path to a PEM file if non-NULL and the
 *               first item in the PEM file will be used as the 
 *               private key.
 *      ca_chain_file: Sets the optional all-in-one file where you 
 *               can assemble the certificates of Certification Authorities 
 *               (CA) which form the certificate chain of the server 
 *               certificate. This starts with the issuing CA certificate 
 *               of the "ssl_cert_file" certificate and can range up to 
 *               the root CA certificate. Such a file is simply the
 *               concatenation of the various PEM-encoded CA Certificate 
 *               files, usually in certificate chain order.  
 *      ciphers: cipher list to use as per ciphers(1). 
 *               May be NULL in which case openssl's default is used.
 * post: If SSL is initiated and a context is created
 *       If cert is non-NULL then this certificate file is loaded
 *       If privkey is non-NULL then this private key file is loaded
 *       If cert and privkey are non-NULL then check private key
 *       against certificate.
 *       Note: If either cert of privkey are non-NULL then both must
 *       be non-NULL.
 *       If chain_file is not null, it must contain alist of (syntactically)
 *       valid pem-encoded certificates 
 *
 **********************************************************************/

SSL_CTX *perdition_ssl_ctx(const char *ca_file, const char *ca_path,
		const char *cert, const char *privkey, 
		const char *ca_chain_file, const char *ciphers);


/**********************************************************************
 * perdition_ssl_client_connection
 * Change a stdio based connection to a remote server, into an SSL 
 * connection.
 * pre: io: io_t to change. A client that has connected to a server, 
 *          SSL_connect() will be called.
 *      ca_file: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      ca_path: certificate authorities to use. May be NULL
 *               See SSL_CTX_load_verify_locations(3)
 *      ciphers: cipher list to use as per ciphers(1). 
 *               May be NULL in which case openssl's default is used.
 *      server: server name to verify with the common name in
 *              the server's certificate
 * post: io_t has an ssl object associated with it and SSL is initiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *perdition_ssl_client_connection(io_t * io, const char *ca_file,
		const char *ca_path, const char *ciphers, const char *server);


/**********************************************************************
 * perdition_ssl_server_connection
 * Change a stdio based connection that revieves client connections,
 * into an SSL connection
 * io: io_t to change
 * ssl_ctx: SSL Context to use
 * post: io_t has an ssl object associated with it and SSL is initiated
 *       for the connection.
 * return: io_t with ssl object associated with it
 *         NULL on error
 **********************************************************************/

io_t *perdition_ssl_server_connection(io_t * io, SSL_CTX * ssl_ctx);

#endif				/* WITH_SSL_SUPPORT */

#endif 				/* _PERDITION_SSL_H */
