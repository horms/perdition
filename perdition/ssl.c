/**********************************************************************
 * ssl.c                                                  November 2001
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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WITH_SSL_SUPPORT

#include "ssl.h"
#include "log.h"
#include "io.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * perdition_ssl_connection
 * Change a stdio bassed connection into an SSL connection
 * io: io_t to change
 * ssl_cts: SSL Context to use
 * flag: If PERDITION_CLIENT the io is a client that has connected to
 *       a server and SSL_connect() will be called. If PERDITION_SERVER
 *       then the io is a server that has accepted a connection and
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
  int ret;
  
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
    ret = SSL_connect(ssl);
    if(ret <= 0){
      PERDITION_DEBUG_SSL_IO_ERR("SSL_connect", io_get_ssl(io), ret);
      goto bail;
    }
  }
  else {
    SSL_set_accept_state(ssl);
    ret = SSL_accept(ssl);
    if(ret <= 0){
      PERDITION_DEBUG_SSL_IO_ERR("SSL_accept", io_get_ssl(io), ret);
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
