/**********************************************************************
 * log.h                                                 September 2000
 * Horms                                             horms@vergenet.net
 *
 * Defines for logging
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
 * Each of the logging macros has two versions. The UNSAFE version will
 * accept a format string. You should _NOT_ use the UNSAFE versions of the
 * first argument, the format string, is derived from user input. The safe
 * versions (versions that do not have the "_UNSAFE" suffix) do not accept
 * a format string and only accept one argument, the string to log. These
 * should be safe to use with user derived input.
 */

#define PERDITION_LOG_UNSAFE(priority, fmt, args...) \
  vanessa_logger_log(perdition_vl, priority, fmt, ## args);

#define PERDITION_LOG(priority, str) \
  vanessa_logger_log(perdition_vl, priority, "%s", str)

#define PERDITION_INFO_UNSAFE(fmt, args...) \
  vanessa_logger_log(perdition_vl, LOG_INFO, fmt, ## args);

#define PERDITION_INFO(str) \
  vanessa_logger_log(perdition_vl, LOG_INFO, "%s", str)

#define PERDITION_ERR_UNSAFE(fmt, args...) \
  vanessa_logger_log(perdition_vl, LOG_ERR, fmt, ## args);

#define PERDITION_ERR(str) \
  vanessa_logger_log(perdition_vl, LOG_ERR, "%s", str)

#define PERDITION_DEBUG_UNSAFE(fmt, args...) \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, __FUNCTION__ ": " fmt, ## args);

#define PERDITION_DEBUG(str) \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, __FUNCTION__ ": %s", str);

#define PERDITION_DEBUG_ERRNO(s) \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, "%s: %s: %s", \
    __FUNCTION__, s, strerror(errno));

#ifdef WITH_SSL_SUPPORT
#define PERDITION_DEBUG_SSL_ERROR_STRING \
  { \
    unsigned long e; \
    while((e=ERR_get_error())) { \
      vanessa_logger_log(perdition_vl, LOG_DEBUG, "%s", \
        ERR_error_string(e, NULL)); \
    } \
  }

#define PERDITION_DEBUG_SSL_ERR_UNSAFE(fmt, args...) \
  PERDITION_DEBUG_SSL_ERROR_STRING \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, fmt, ## args);

#define PERDITION_DEBUG_SSL_ERR(str) \
  PERDITION_DEBUG_SSL_ERROR_STRING \
  vanessa_logger_log(perdition_vl, LOG_DEBUG, __FUNCTION__ ": %s", str)
#endif /* WITH_SSL_SUPPORT */

#endif
