/**********************************************************************
 * config_file.h                                          November 1999
 * Horms                                             horms@vergenet.net
 *
 * Read in a config and parse it into command line arguments,
 * return this as a dynamic array
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


#ifndef CONFIG_FILE_BERT
#define CONFIG_FILE_BERT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <vanessa_adt.h>

#include "options.h"

/* Flags for config_file_to_opt */
#define CONFIG_FILE_ERR (flag_t) 0x1    /*Log errors to stderr*/

void config_file_to_opt(const char *filename);
vanessa_dynamic_array_t *config_file_read (const char *filename);
void config_file_reread_handler(int sig);

#endif
