/**********************************************************************
 * config_file.c                                          November 1999
 * Horms                                             horms@vergenet.net
 *
 * Read in a config and parse it into command line arguments,
 * return this as a dynamic array
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


#include "config_file.h"

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

  if((a=config_file_read(filename))==NULL){
    return;
  }
  
  /* Set options according to config file but only if they are not 
   * Masked (overriden on the command line)
   */

  options(
    vanessa_dynamic_array_get_count(a),
    (char **)vanessa_dynamic_array_get_vector(a),
    OPT_USE_MASK|OPT_FILE
  );

  vanessa_dynamic_array_destroy(a);

  return;
}


/**********************************************************************
 * config_file_read
 * Read in a config file and put elements in a dynamic array
 * pre: filename: file to read configuration from
 * return: dynamic array containin elements, keys are preceded by
 *         a -- and must be long opts as per options.c.
 *         If a key is a single letter it is preceded by a -
 *         and must be a short opt as per options.c
 *         A key is the first whitespace delimited word on a line
 *         Blank lines are ignored.
 *         Everthing including and after a hash (#) on a line is 
 *         ignored
 **********************************************************************/

vanessa_dynamic_array_t *config_file_read (const char *filename){
  char key[MAX_LINE_LENGTH+3];
  char tail[MAX_LINE_LENGTH+1];
  char format[MAX_LINE_LENGTH];
  int status;
  int token=0;
  int comment=0;
  char *s;
  vanessa_dynamic_array_t *a;
  FILE *stream;

  extern int errno;

  if(filename==NULL) return(NULL);
  if((stream=fopen(filename, "r"))==NULL){
    PERDITION_LOG(
      LOG_DEBUG, 
      "config_file_read: fopen(%s): %s", 
      filename,
      strerror(errno)
    );
    return(NULL);
  }

  if((a=vanessa_dynamic_array_create(
	0,
	VANESSA_DESTROY_STR,
	VANESSA_DUPLICATE_STR,
	VANESSA_DISPLAY_STR,
	VANESSA_LENGTH_STR))==NULL){
    PERDITION_LOG(LOG_DEBUG, "config_file_read: vanessa_dynamic_array_create");
    return(NULL);
  }
  /*insert a dummy argv[0] into the dynamic array*/
  if((a=vanessa_dynamic_array_add_element(a, ""))==NULL){
    PERDITION_LOG(
      LOG_DEBUG, 
      "config_file_read: vanessa_dynamic_array_add_element"
    );
    return(NULL);
  }

  *key='-';
  *(key+1)='-';
  if(snprintf(
    format,
    MAX_LINE_LENGTH,
    "%%%d[^ \t\n\r#]%%%d[ \t\n\r#]",
    MAX_LINE_LENGTH, 
    MAX_LINE_LENGTH
  )<0){
    PERDITION_LOG(LOG_DEBUG, "config_file_read: snprintf");
    return(NULL);
  }

  while((status=fscanf(stream, format, key+2, tail))!=EOF){
    if(status==0) { status=fscanf(stream, "%[^\n]\n", tail); continue; }
    if(!comment){
      if((a=vanessa_dynamic_array_add_element(
        a, 
        key+(token==0?((*(key+3)=='\0')?1:0):2)
      ))==NULL){
        PERDITION_LOG(
	  LOG_DEBUG, 
	  "config_file_read: vanessa_dynamic_array_add_element"
	);
        return(NULL);
      }
    }
    if(status==2){
      if((s=strrchr(tail, '\n'))==NULL){
        token++;
      }
      else{
        token=0;
        comment=0;
      }
      if(!comment){
        comment=(strchr(s!=NULL?s:tail, '#')==NULL)?0:1;
      }
    }
  }
  return(a);
}


/**********************************************************************
 * config_file_reread_handler
 * A signal handler that rereads the config file on signal
 * and resets the signal handler
 * pre: sig: signal recieved by the process
 * post: config file reread
 *       signal handler reset for signal
 **********************************************************************/

void config_file_reread_handler(int sig){
  extern options_t opt;

  config_file_to_opt(opt.config_file);
  PERDITION_LOG(LOG_INFO, "Config file reread on signal (%d)\n", sig);
  log_options();
  signal(sig, (void(*)(int))config_file_reread_handler);
  return;
}

