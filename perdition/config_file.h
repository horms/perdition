/**********************************************************************
 * config_file.h                                          November 1999
 * Horms                                             horms@vergenet.net
 *
 * Read in a config and parse it into command line arguments,
 * return this as a dynamic array
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


#ifndef _CONFIG_FILE_H
#define _CONFIG_FILE_H

#include <stdlib.h>

/**********************************************************************
 * config_file_to_opt
 * Configure opt structire according to options specified in a config
 * file.
 * pre: filename: file to read options from
 * post: options in global options_t opt are set according to
 *       config file. Options specified onthe command line
 *       override config file options
 **********************************************************************/

void config_file_to_opt(const char *filename);

char *config_file_name(const char *basename, int protocol);

#endif /* _CONFIG_FILE_H */
