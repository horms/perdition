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

#define PERDITION_LOG(priority, fmt, args...) \
  vanessa_logger_log(perdition_vl, priority, fmt, ## args);

#define PERDITION_INFO(fmt, args...) \
  PERDITION_LOG(LOG_INFO, fmt, ## args);

#define PERDITION_ERR(fmt, args...) \
  PERDITION_LOG(LOG_ERR, fmt, ## args);

#define PERDITION_DEBUG(fmt, args...) \
  PERDITION_LOG(LOG_DEBUG, __FUNCTION__ ": " fmt, ## args);

#define PERDITION_DEBUG_ERRNO(s) \
  PERDITION_LOG(LOG_DEBUG, "%s: %s: %s", __FUNCTION__, s, strerror(errno));

#ifdef WITH_SSL_SUPPORT
#define PERDITION_DEBUG_SSL_ERR(fmt, args...) \
  { \
    unsigned long e; \
    while((e=ERR_get_error())){ \
      PERDITION_DEBUG("%s", ERR_error_string(e, NULL)); \
    } \
  } \
  PERDITION_DEBUG(fmt, ## args);
#endif /* WITH_SSL_SUPPORT */




#endif
