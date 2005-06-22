/**********************************************************************
 * log.h                                                 September 2000
 * Horms                                             horms@verge.net.au
 *
 * Defines for logging
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifndef _PERDITION_LOG_H
#define _PERDITION_LOG_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WITH_SSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /* WITH_SSL_SUPPORT */

#include <vanessa_logger.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#define LOG_IDENT "perdition"

/*
 * Hooray for format string problems!
 *
 * Each of the logging macros have two versions. The UNSAFE version will
 * accept a format string. You should _NOT_ use the UNSAFE versions if the
 * first argument, the format string, is derived from user input. The safe
 * versions (versions that do not have the "_UNSAFE" suffix) do not accept
 * a format string and only accept one argument, the string to log. These
 * should be safe to use with user derived input.
 */

#ifdef WITH_SSL_SUPPORT
#define PERDITION_DEBUG_SSL_ERROR_STRING                                      \
  {                                                                           \
    unsigned long e;                                                          \
    SSL_load_error_strings();                                                 \
    while((e=ERR_get_error())) {                                              \
      VANESSA_LOGGER_DEBUG(ERR_error_string(e, NULL));                        \
    }                                                                         \
    ERR_free_strings();                                                       \
  }

#define PERDITION_DEBUG_SSL_IO_ERR(str, ssl, ret)                             \
{                                                                             \
  int error;                                                                  \
  error = SSL_get_error(ssl, ret);                                            \
  if(error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0) {                   \
    if(ret == 0) {                                                            \
      VANESSA_LOGGER_DEBUG(str ": An EOF that violates the protocol "         \
                      "has occurred");                                         \
    }                                                                         \
    else if(ret == -1) {                                                      \
      VANESSA_LOGGER_DEBUG_ERRNO(str ": I/O Error");                          \
    }                                                                         \
    else {                                                                    \
      VANESSA_LOGGER_DEBUG(str ": Unknown Syscall Error");                    \
    }                                                                         \
  }                                                                           \
  else if(error == SSL_ERROR_ZERO_RETURN) {                                   \
    VANESSA_LOGGER_DEBUG(str ": Connection has closed");                      \
  }                                                                           \
  else if(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {    \
    VANESSA_LOGGER_DEBUG(str ": Warning: wants read or write");               \
  }                                                                           \
  /* SSL_ERROR_WANT_ACCEPT does not appear to be defined for some reason      \
  else if(error == SSL_ERROR_WANT_CONNECT || error == SSL_ERROR_WANT_ACCEPT) {\
    VANESSA_LOGGER_DEBUG(str ": Warning: wants connect or accept");           \
  }                                                                           \
  */                                                                          \
  else if(error == SSL_ERROR_WANT_CONNECT) {                                  \
    VANESSA_LOGGER_DEBUG(str ": Warning: wants connect");                     \
  }                                                                           \
  else if(error == SSL_ERROR_WANT_X509_LOOKUP) {                              \
    VANESSA_LOGGER_DEBUG(str ": Warning: wants x509 lookup");                 \
  }                                                                           \
  else {                                                                      \
    PERDITION_DEBUG_SSL_ERR(str);                                             \
  }                                                                           \
}

#define PERDITION_DEBUG_SSL_ERR_UNSAFE(fmt, args...)                          \
  PERDITION_DEBUG_SSL_ERROR_STRING                                            \
  vanessa_logger_log(vanessa_logger_get(), LOG_DEBUG, fmt, ## args)

#define PERDITION_DEBUG_SSL_ERR(str)                                          \
  PERDITION_DEBUG_SSL_ERROR_STRING                                            \
  VANESSA_LOGGER_DEBUG(str)
#endif /* WITH_SSL_SUPPORT */

#endif /* _PERDITION_LOG_H */
