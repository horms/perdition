/**********************************************************************
 * config_file.c                                          November 1999
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "config_file.h"

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

#define ADD_TOKEN(_a, _t) \
  if((_a=vanessa_dynamic_array_add_element(_a, _t))==NULL){ \
    PERDITION_DEBUG("config_file_read: vanessa_dynamic_array_add_element"); \
    close(fd); \
    return(NULL); \
  }

#define BEGIN_KEY \
  if(!in_escape && !in_comment && !in_quote){ \
    in_key=1; \
  } \

#define END_KEY \
  if(!in_escape && in_key && !in_quote){ \
    if(in_key && token_pos){ \
      *(token_buffer+token_pos+2)='\0'; \
      ADD_TOKEN(a, ((token_pos==1)?token_buffer+1:token_buffer)) ; \
    } \
    token_pos=0; \
    in_key=0; \
  } \

#define BEGIN_VALUE \
  if(!in_key && !in_comment && !in_quote){ \
    in_value=1; \
  } \

#define END_VALUE \
  if(!in_escape && in_value && !in_quote){ \
    if(in_value){ \
      *(token_buffer+token_pos+2)='\0'; \
      ADD_TOKEN(a, token_buffer+2) ; \
    } \
    token_pos=0; \
    in_value=0; \
  } \

#define END_COMMENT \
  if(!in_escape){ \
    in_comment=0; \
  } \

#define BEGIN_COMMENT \
  if(!in_escape && !in_quote){ \
    in_comment=1; \
  } \

#define BEGIN_ESCAPE \
  in_escape=1;

#define END_ESCAPE \
  in_escape=0;

#define SINGLE_QUOTE 1
#define DOUBLE_QUOTE 2

vanessa_dynamic_array_t *config_file_read (const char *filename){
  vanessa_dynamic_array_t *a;
  size_t token_pos;
  size_t nread;
  char token_buffer[MAX_LINE_LENGTH];
  char read_buffer[MAX_LINE_LENGTH];
  char c;
  int max_token_pos=MAX_LINE_LENGTH-3;
  int read_pos;
  int fd;

  int in_escape  = 0;
  int in_comment = 0;
  int skip_char  = 0;
  int in_value   = 0;
  int in_quote   = 0;
  int in_key     = 0;

  extern int errno;

  if(filename==NULL) return(NULL);
  if((fd=open(filename, O_RDONLY))<0){
    PERDITION_DEBUG_UNSAFE("open(%s): %s", filename, strerror(errno));
    return(NULL);
  }

  if((a=vanessa_dynamic_array_create(
	0,
	VANESSA_DESTROY_STR,
	VANESSA_DUPLICATE_STR,
	VANESSA_DISPLAY_STR,
	VANESSA_LENGTH_STR
  ))==NULL){
    PERDITION_DEBUG("vanessa_dynamic_array_create");
    return(NULL);
  }

  /*insert a dummy argv[0] into the dynamic array*/
  ADD_TOKEN(a, "");

  *token_buffer='-';
  *(token_buffer+1)='-';
  token_pos=0;

  while(1){
    if((nread=read(fd, read_buffer, MAX_LINE_LENGTH))<0){
      if(errno==EINTR){
	continue;
      }
      PERDITION_DEBUG("read");
      vanessa_dynamic_array_destroy(a);
      close(fd);
      return(NULL);
    }
    if(nread==0){
      break;
    }

    for(read_pos=0;read_pos<nread;read_pos++){
      c=*(read_buffer+read_pos);

      switch(c){
	case ' ': case '\t':
	  END_KEY;
	  if(in_escape){
            BEGIN_VALUE;
	  }
	  END_ESCAPE;
	  break;
	case '\n': case '\r':
	  END_KEY;
	  END_COMMENT;
	  END_VALUE;
	  BEGIN_KEY;
	  END_ESCAPE;
	  break;
	case '\\':
	  if(in_escape || in_quote ) {
	    END_ESCAPE;
	  }
	  else {
	    BEGIN_ESCAPE;
	  }
          BEGIN_VALUE;
	  break;
	case '#':
	  BEGIN_COMMENT;
	  END_KEY;
	  END_VALUE;
          BEGIN_VALUE;
	  END_ESCAPE;
	  break;
	case '"':
          BEGIN_VALUE;
	  if(!in_escape && !in_comment && !(in_quote&SINGLE_QUOTE)){
	    if(in_quote&DOUBLE_QUOTE){
	      in_quote^=in_quote&DOUBLE_QUOTE;
	    }
	    else{
	      in_quote|=DOUBLE_QUOTE;
	    }
	    skip_char=1;
	  }
	  END_ESCAPE;
          break;
	case '\'':
          BEGIN_VALUE;
	  if(!in_escape && !in_comment){
	    if(in_quote&SINGLE_QUOTE){
	      in_quote^=SINGLE_QUOTE;
	    }
	    else{
	      in_quote|=SINGLE_QUOTE;
	    }
	    skip_char=1;
	  }
	  END_ESCAPE;
          break;
	default:
	  BEGIN_VALUE;
	  END_ESCAPE;
	  break;
      }

      if(
	in_key|in_value && 
	c!='\n' && 
	c!='\r' && 
	!in_escape && 
	!skip_char && 
	token_pos<max_token_pos
      ){
        *(token_buffer+token_pos+2)=c;
        token_pos++;
      }
      skip_char=0;
    }
  }

  close(fd);
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
  PERDITION_INFO_UNSAFE("Config file reread on signal (%d)\n", sig);
  log_options();
  signal(sig, (void(*)(int))config_file_reread_handler);
  return;
}

