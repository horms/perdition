/**********************************************************************
 * log.h                                                 September 2000
 * Horms                                             horms@vergenet.net
 *
 * Defines for logging
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

#ifndef SYSLOG_BERT
#define SYSLOG_BERT

#ifdef HAVE_CONFIG_H
#include "../config.h"
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

extern vanessa_logger_t *perdition_vl;
extern int errno;


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

#define PERDITION_LOG_UNSAFE(priority, fmt, args...) \
  vanessa_logger_log(perdition_vl, priority, fmt, ## args)

#define PERDITION_LOG(priority, str) \
  vanessa_logger_log(perdition_vl, priority, "%s", str)

#define PERDITION_INFO_UNSAFE(fmt, args...) \
  vanessa_logger_log(perdition_vl, LOG_INFO, fmt, ## args)

#define PERDITION_INFO(str) \
  vanessa_logger_log(perdition_vl, LOG_INFO, "%s", str)

#define PERDITION_ERR_UNSAFE(fmt, args...) \
  vanessa_logger_log(perdition_vl, LOG_ERR, fmt, ## args)

#define PERDITION_ERR(str) \
  vanessa_logger_log(perdition_vl, LOG_ERR, "%s", str)

#define PERDITION_DEBUG_UNSAFE(fmt, args...) \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, __FUNCTION__ ": " fmt, ## args)

#define PERDITION_DEBUG(str) \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, __FUNCTION__ ": %s", str)

#define PERDITION_DEBUG_ERRNO(s) \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, "%s: %s: %s", \
    __FUNCTION__, s, strerror(errno))

#ifdef WITH_SSL_SUPPORT
#define PERDITION_DEBUG_SSL_ERROR_STRING \
  { \
    unsigned long e; \
    SSL_load_error_strings(); \
    while((e=ERR_get_error())) { \
      vanessa_logger_log(perdition_vl, LOG_DEBUG, "%s", \
        ERR_error_string(e, NULL)); \
    } \
    ERR_free_strings(); \
  }

#define PERDITION_DEBUG_SSL_IO_ERR(str, ssl, ret) \
{ \
  int error; \
  error = SSL_get_error(ssl, ret); \
  if(error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0) { \
    if(ret == 0) { \
      PERDITION_DEBUG(str ": An EOF that violates the protocol " \
                      "has occured"); \
    } \
    else if(ret == -1) { \
      PERDITION_DEBUG_ERRNO(str ": I/O Error"); \
    } \
    else { \
      PERDITION_DEBUG(str ": Unknown Syscall Error"); \
    } \
  } \
  else if(error == SSL_ERROR_ZERO_RETURN) { \
    PERDITION_DEBUG(str ": Connection has closed"); \
  } \
  else if(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) { \
    PERDITION_DEBUG(str ": Warning: wants read or write"); \
  } \
  /* SSL_ERROR_WANT_ACCEPT does not appear to be defined for some reason \
  else if(error == SSL_ERROR_WANT_CONNECT || error == SSL_ERROR_WANT_ACCEPT) { \
    PERDITION_DEBUG(str ": Warning: wants connect or accept"); \
  } \
  */ \
  else if(error == SSL_ERROR_WANT_CONNECT) { \
    PERDITION_DEBUG(str ": Warning: wants connect"); \
  } \
  else if(error == SSL_ERROR_WANT_X509_LOOKUP) { \
    PERDITION_DEBUG(str ": Warning: wants x509 lookup"); \
  } \
  else { \
    PERDITION_DEBUG_SSL_ERR(str); \
  } \
}

#define PERDITION_DEBUG_SSL_ERR_UNSAFE(fmt, args...) \
  PERDITION_DEBUG_SSL_ERROR_STRING \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, fmt, ## args)

#define PERDITION_DEBUG_SSL_ERR(str) \
  PERDITION_DEBUG_SSL_ERROR_STRING \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, __FUNCTION__ ": %s", str)
#endif /* WITH_SSL_SUPPORT */

#endif
