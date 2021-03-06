/**********************************************************************
 * config_file.h                                          November 1999
 * Horms                                             horms@verge.net.au
 *
 * Read in a config and parse it into command line arguments,
 * return this as a dynamic array
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 **********************************************************************/


#ifndef _CONFIG_FILE_H
#define _CONFIG_FILE_H

#include <stdlib.h>

/**********************************************************************
 * config_file_to_opt
 * Configure opt structure according to options specified in a config
 * file.
 * pre: filename: file to read options from
 * post: options in global options_t opt are set according to
 *       config file. Options specified on the command line
 *       override config file options
 **********************************************************************/

void config_file_to_opt(const char *filename);

char *config_file_name(const char *basename, int protocol);

#endif /* _CONFIG_FILE_H */
