/**********************************************************************
 * config_file.c                                          November 1999
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <vanessa_adt.h>

#include "config_file.h"
#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * config_file_to_opt
 * Configure opt structire according to options specified in a config
 * file.
 * pre: filename: file to read options from
 * post: options in global options_t opt are set according to
 *       config file. Options specified onthe command line
 *       override config file options
 **********************************************************************/

void config_file_to_opt(const char *filename){
  vanessa_dynamic_array_t *a;

  VANESSA_LOGGER_DEBUG_RAW_UNSAFE("Reading configuration file: \"%s\"",
		  filename);
  a=vanessa_config_file_read(filename, 0);
  if(!a) {
    return;
  }
  
  /* 
   * Set options according to config file but only if they are not 
   * Masked (overriden on the command line)
   */
  options(vanessa_dynamic_array_get_count(a),
    (char **)vanessa_dynamic_array_get_vector(a), OPT_USE_MASK|OPT_FILE);

  vanessa_dynamic_array_destroy(a);

  return;
}
