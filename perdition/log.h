/**********************************************************************
 * log.h                                                 September 2000
 * Horms                                             horms@vergenet.net
 *
 * Defines for logging
 *
 * perdition
 * Mail retreival proxy server
 * Copyright (C) 1999  Horms
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

#include <vanessa_logger.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#define LOG_IDENT "perdition"
#define LOG_FACILITY LOG_MAIL

extern vanessa_logger_t *perdition_vl;

#define PERDITION_LOG(priority, fmt, args...) \
  vanessa_logger_log(perdition_vl, priority, fmt, ## args);

#endif
