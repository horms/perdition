/**********************************************************************
 * config_file.c                                          November 1999
 * Horms                                             horms@verge.net.au
 *
 * Read in a config and parse it into command line arguments,
 * return this as a dynamic array
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2004  Horms
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
 * Configure opt structure according to options specified in a config
 * file.
 * pre: filename: file to read options from
 * post: options in global options_t opt are set according to
 *       config file. Options specified on the command line
 *       override config file options
 **********************************************************************/

void config_file_to_opt(const char *filename){
  vanessa_dynamic_array_t *a;

  if(!filename || !*filename) {
    return;
  }

  VANESSA_LOGGER_DEBUG_RAW_UNSAFE("Reading configuration file: \"%s\"",
		  filename);
  a=vanessa_config_file_read(filename, 0);
  if(!a) {
    return;
  }
  
  /* 
   * Set options according to config file but only if they are not 
   * Masked (overridden on the command line)
   */
  options(vanessa_dynamic_array_get_count(a),
    (char **)vanessa_dynamic_array_get_vector(a), OPT_USE_MASK|OPT_FILE);

  vanessa_dynamic_array_destroy(a);

  return;
}


#define __CONFIG_FILE_NAME_EXISTS                                      \
        status = vanessa_config_file_check_exits(configuration_file);  \
	if(!status) {                                                  \
		return(configuration_file);                            \
	}                                                              \
	free(configuration_file);                                      \
	configuration_file=NULL;

#define CONFIG_FILE_NAME_BASE   "perdition"
#define CONFIG_FILE_NAME_SUFFIX ".conf"

char *config_file_name(const char *basename, int protocol) 
{
	int status = -1;
	char *configuration_file = NULL;
	const char *suffix;

	if(strcmp(basename, CONFIG_FILE_NAME_BASE)) {
		configuration_file = str_cat(3, PERDITION_SYSCONFDIR "/", 
				basename, CONFIG_FILE_NAME_SUFFIX);
		if(!configuration_file) {
			VANESSA_LOGGER_DEBUG("str_cat");
			goto leave;
		}
		__CONFIG_FILE_NAME_EXISTS;
	}

	suffix = NULL;
	switch(protocol) {
		case PROTOCOL_IMAP4:
			suffix = "imap4";
			break;
		case PROTOCOL_IMAP4S:
			suffix = "imap4s";
			break;
		case PROTOCOL_POP3:
			suffix = "pop3";
			break;
		case PROTOCOL_POP3S:
			suffix = "pop3s";
			break;
	}
	if(!suffix) {
		VANESSA_LOGGER_DEBUG_UNSAFE("Unknown protocol \"%d\"",
				protocol);
		goto leave;
	}

	configuration_file = str_cat(4, PERDITION_SYSCONFDIR "/",
			CONFIG_FILE_NAME_BASE "." , suffix, 
			CONFIG_FILE_NAME_SUFFIX);
	__CONFIG_FILE_NAME_EXISTS;

	configuration_file = str_cat(3, PERDITION_SYSCONFDIR "/",
			CONFIG_FILE_NAME_BASE, CONFIG_FILE_NAME_SUFFIX);
	__CONFIG_FILE_NAME_EXISTS;

leave:
	if(configuration_file) {
		free(configuration_file);
	}
	return(NULL);
}
