/**********************************************************************
 * perditiondb_posix_regex.c                              December 1999
 * Horms                                             horms@vergenet.net
 *
 * Access a posix_regex map
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

#include "perditiondb_posix_regex.h"

static vanessa_dynamic_array_t *regex_a;


/**********************************************************************
 * dbserver_init
 * Read the server information for a given key from the posix_regex map
 * pre: options_str: options string to use
 *                   Specifies the name of the regex map to open
 *                   If NULL then PERDITIONDB_POSIX_REGEX_MAPNAME
 *                   is used
 * post: regex map is opened, regex are compiled and stored with
 *       their server in the static vanessa_dynamic_array_t *regex_a
 * return:  0 on success
 *         -1 on file access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_init(char *options_str){
  vanessa_key_value_t *kv=NULL;
  regex_t *preg=NULL;
  FILE *stream=NULL;
  char *line=NULL;
  char *line_cur;
  char *line_end;
  char *regex;
  char *server_port_str;
  int blank;

  extern int errno;

  regex_a=NULL;
 
  if((stream=fopen(
    (options_str==NULL)?PERDITIONDB_POSIX_REGEX_MAPNAME:options_str, "r")
  )==NULL){
    PERDITION_DEBUG_UNSAFE(
      "Could not open %s: %s\n",
      (options_str==NULL)?PERDITIONDB_POSIX_REGEX_MAPNAME:options_str,
      strerror(errno)
    );
    return(-1);
  }

  if((line=(char *)malloc(PERDITIONDB_POSIX_REGEX_MAX_LINE_LENGTH))==NULL){
    PERDITION_DEBUG_ERRNO("malloc 1");
    goto leave_3;
  }
  if((regex_a=vanessa_dynamic_array_create(
	0,
	VANESSA_DESTROY_KV,
	VANESSA_DUPLICATE_KV,
	NULL,
	NULL
  ))==NULL){ 
    goto leave_3; 
  }
  if((kv=vanessa_key_value_create())==NULL){ 
    goto leave_3; 
  }

  line_end=line+PERDITIONDB_POSIX_REGEX_MAX_LINE_LENGTH;
  while(fgets(line, PERDITIONDB_POSIX_REGEX_MAX_LINE_LENGTH, stream)!=NULL){
    blank=1;
    regex=line;
    server_port_str=NULL;
    *line_end='\0';
    for(line_cur=line;line_cur<line_end;line_cur++){
      if(*line_cur=='\0'||*line_cur=='\n'||*line_cur=='\r' || *line_cur=='#'){
        *line_cur='\0';
        break;
      }
      if(blank && *line_cur!=' ' && *line_cur!='\t'){
        blank=0;
      }
      if(blank){
        (server_port_str==NULL)?regex++:server_port_str++;
      }
      if(
        server_port_str==NULL && 
        *line_cur==PERDITIONDB_POSIX_REGEX_MAX_FIELD_DELIMITER
      ){
        *line_cur='\0';
        server_port_str=line_cur+1;
        blank=1;
        continue;
      }
    }
    if(blank||(*regex=='\0'||server_port_str==NULL||*server_port_str=='\0')){
      continue;
    }
    if((preg=(regex_t *)malloc(sizeof(regex_t)))==NULL){ 
      PERDITION_DEBUG_ERRNO("malloc 2");
      goto leave_3; 
    }
    if(regcomp(preg, regex, REG_EXTENDED|REG_NEWLINE)){
      goto leave_3;
    }
    if((kv=vanessa_key_value_assign(
      kv, 
      (void *)preg, 
      DESTROY_REGEX, 
      NULL,
      (void *)server_port_str,
      VANESSA_DESTROY_STR,
      VANESSA_DUPLICATE_STR
    ))==NULL){ 
      goto leave_3; 
    }
    if(vanessa_dynamic_array_add_element(regex_a,kv)==NULL){
      goto leave_3;
    }
  }

  fclose(stream);
  free(line);
  return(0);
  free(kv);

  leave_3:
  if(stream!=NULL){ fclose(stream); }
  if(line!=NULL){ free(line); }
  if(regex_a!=NULL){ 
    vanessa_dynamic_array_destroy(regex_a); 
  }
  if(preg!=NULL){ destroy_regex(preg); }
  if(kv!=NULL){ vanessa_key_value_destroy(kv); }
  return(-3);
} 


/**********************************************************************
 * dbserver_get
 * Find the server for a given user
 * pre: key_str: user to find server for
 *      options_str: options string
 *                   ignored
 *      str_return:  Value is returned here
 *      len_return:  Length of value is returned here
 * post: The str_key is looked up and the corresponding value is 
 *       returned in str_return and len_return.
 * return:  0 on success
 *         -1 on file access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 * Note: The string returned in str_return should be of the 
 * form <servername>[:<port>].
 * E.g.: localhost:110
 *       localhost 
 *
 * Back referance replacement is done in the result, so that you can write
 * rules such as:
 * ([^.]*)@([^.]*)\.(.*):      $1_$2_$3@realimapserver
 *                             by Wim Bonis <bonis@solution-service.de>
 * The code from php3
 **********************************************************************/

/* Maximum number of (..) constructs */
#define  REXEX_NOSUBMATCH  10

int dbserver_get(
  char *key_str, 
  char *options_str,
  char **str_return, 
  int  *len_return
){
  int i;
  int pos;
  int tmp;
  int new_l;
  int status;
  int buf_len;
  int string_len;
  char *buf;        /* buf is where we build the replaced string */
  char *nbuf;       /* nbuf is used when we grow the buffer */
  char *walkbuf;    /* used to walk buf when replacing backrefs */
  char *replace;
  const char *walk; /* used to walk replacement string for backrefs */
  regmatch_t subs[REXEX_NOSUBMATCH];
  vanessa_key_value_t *kv;


  string_len = strlen(key_str);

  for(i=vanessa_dynamic_array_get_count(regex_a)-1;i>=0;i--){

    /* 
     * Start with a buffer that is twice the size of the string
     * we're doing replacements in 
     */
    buf_len = 2 * string_len + 1;
    if((buf=malloc(buf_len*sizeof(char)))==NULL){
      PERDITION_DEBUG_ERRNO("malloc 1");
      return(-3);
    }

    pos = 0;
    buf[0] = '\0';
      
    kv=vanessa_dynamic_array_get_element(regex_a,i);
    status=regexec(
      (regex_t *)vanessa_key_value_get_key(kv), 
      key_str, 
      (size_t) REXEX_NOSUBMATCH, 
      subs, 
      0
    );
    if(!status){
      replace=(char *)vanessa_key_value_get_value(kv);
      /* backref replacement is done in two passes:
       * 1) find out how long the string will be, and allocate buf
       * 2) copy the part before match, replacement and backrefs to buf
       *
       * Jaakko Hyvätti <Jaakko.Hyvatti@iki.fi>
       */

      new_l = strlen(buf) + subs[0].rm_so; /* part before the match */
      walk = replace;
      while(*walk){
      	if(
	  '$' == *walk
	  && '0' <= walk[1] && '9' >= walk[1]
	  && subs[walk[1] - '0'].rm_so > -1
      	  && subs[walk[1] - '0'].rm_eo > -1
        ){
	  new_l += subs[walk[1] - '0'].rm_eo - subs[walk[1] - '0'].rm_so;
	  walk += 2;
	} 
	else {
	  new_l++;
	  walk++;
	}
      }
      
      if (new_l + 1 > buf_len) {
  	buf_len = 1 + buf_len + 2 * new_l;
	if((nbuf=malloc(buf_len))==NULL){
  	  PERDITION_DEBUG_ERRNO("malloc 2");
	  free(buf);
	  return(-3);
	}
	strcpy(nbuf, buf);
	free(buf);
       	buf = nbuf;
      }
      tmp = strlen(buf);
      /* copy the part of the string before the match */
      strncat(buf, &key_str[pos], subs[0].rm_so);
      
      /* copy replacement and backrefs */
      walkbuf = &buf[tmp + subs[0].rm_so];
      walk = replace;
      while(*walk){
     	if(
	  '$' == *walk
	  && '0' <= walk[1] && '9' >= walk[1]
	  && subs[walk[1] - '0'].rm_so > -1
	  && subs[walk[1] - '0'].rm_eo > -1
 	  ){
	  tmp = subs[walk[1] - '0'].rm_eo - subs[walk[1] - '0'].rm_so;
	  memcpy (walkbuf, &key_str[pos + subs[walk[1] - '0'].rm_so], tmp);
	  walkbuf += tmp;
	  walk += 2;
	} 
	else{
	  *walkbuf++ = *walk++;
	}
      }
      *walkbuf = '\0';
      
      /* and get ready to keep looking for replacements */
      if(subs[0].rm_so == subs[0].rm_eo){
     	if(subs[0].rm_so + pos >= string_len){
  	  break;
	}
	new_l = strlen (buf) + 1;
	if(new_l + 1 > buf_len){
	  buf_len = 1 + buf_len + 2 * new_l;
	  nbuf = malloc(buf_len * sizeof(char));
	  if((nbuf=malloc(buf_len))==NULL){
  	    PERDITION_DEBUG_ERRNO("malloc 3");
	    free(buf);
	    return(-3);
	  }
	  strcpy(nbuf, buf);
	  free(buf);
	  buf = nbuf;
	}
	pos += subs[0].rm_eo + 1;
	buf [new_l-1] = key_str [pos-1];
	buf [new_l] = '\0';
      } 
      else{
	pos += subs[0].rm_eo;
      }
      buf [new_l] = '\0'; 
      
      *str_return=buf;
      *len_return=strlen(buf);
      return(0);
    }
  }
  
  return(-2);
} 


/**********************************************************************
 * dbserver_fini
 * Free memory structures associated with the regex map
 * pre: none
 * post: static vanessa_dynamic_array_t *regex_t is freed
 * return:  0 on success
 *         -1 on file access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_fini(void){
  vanessa_dynamic_array_destroy(regex_a);
  return(0);
}


/**********************************************************************
 * dummy_dup_regex
 * Dummy function to duplicate a regex.
 * Does nothing, returns preg, not a copy
 * pre: preg: regex to copy
 * post: nothing
 * return: preg
 **********************************************************************/

static regex_t *dummy_dup_regex(regex_t *preg){
  return(preg);
}


/**********************************************************************
 * destroy_regex
 * Free up the memory associated with a regex
 * pre: preg: regex to free
 * post: regex structure and contents is freed
 * return: nothing
 **********************************************************************/

static void destroy_regex(regex_t *preg){
  regfree(preg);
  free(preg);
}

