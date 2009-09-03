/**********************************************************************
 * makegdbm.c                                                  May 1999
 * Horms                                             horms@verge.net.au
 *
 * Create a gdbm file from a : delimited flat file read from stdin
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>

#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


#define MAX_LINE_LENGTH 4096
#define FIELD_DELIMITER ':'

void makegdbm_new(const makegdbm_options_t options);
void makegdbm_undo(const makegdbm_options_t options);

int main(int argc, char **argv){
  makegdbm_options_t options;

  options=makegdbm_options(argc, argv);


  if(options.undo){
    makegdbm_undo(options);
  }
  else{
    makegdbm_new(options);
  }

  return(0);
}
  

/**********************************************************************
 * makegdbm_new
 * Create a nrew gdbm file from a flat file read from stdin
 * pre: options: options structure specifying what to do
 * post: gdbm file created and populated
 **********************************************************************/

void makegdbm_new(const makegdbm_options_t options){
  GDBM_FILE dbf;
  datum key;
  datum content;
  int i;
  char line[MAX_LINE_LENGTH];
  int status;
  int blank;
  int lineno;

  if((dbf=gdbm_open(options.mapname, 0, GDBM_NEWDB|GDBM_FAST, 0644, 0))==NULL){
    fprintf(
      stderr, 
      "makegdbm_new: gdbm_open: %s: %s\n", 
      gdbm_strerror(gdbm_errno), 
      strerror(errno)
    );
    exit(-1);
  }

  /*Warning: This loop contains some of the worst code ever written*/
  status=0;
  lineno=0;
  while(fgets(line, MAX_LINE_LENGTH, stdin)!=NULL){
    blank=1;
    key.dptr=line;
    key.dsize=-1;
    content.dsize=-1;
    for(i=0;i<MAX_LINE_LENGTH;i++){
      if(blank && *(line+i)!=' ' && *(line+i)!='\t'&& *(line+i)!='\n'){
        blank=0;
      }
      if(key.dsize==-1 && *(line+i)==FIELD_DELIMITER){
        key.dsize=i;
        content.dptr=line+i+1;
        continue;
      }
      if(content.dsize==-1 && *(line+i)=='\n'){
        content.dsize=i-key.dsize-1;
        lineno++;
        break;
      }
    }
    fflush(NULL);
    if(!blank && !status && (key.dsize<1 || content.dsize<1)){
      status=1;
    }
    if(status){
      if(*(line+i)=='\n'){
        fprintf(stderr, "makegdbm: invalid input on line: %d \n", lineno);
        status=0;
      }
      continue;
    }

    if(blank){
      continue;
    }
    if(gdbm_store(dbf, key, content, GDBM_INSERT)>0){
      *(key.dptr+key.dsize)='\0';
      fprintf(stderr, "makegdbm: dupicate key: %s\n", key.dptr);
    }

  }

  gdbm_close(dbf);
}


/**********************************************************************
 * makegdbm_undo
 * print out a : delimited flat file to stdout of a gdbm file
 * pre: options: options structure sepcifying what to do
 * post: glat file output to stdout
 **********************************************************************/

void makegdbm_undo(makegdbm_options_t options){
  GDBM_FILE dbf;
  datum this_key;
  datum next_key;
  datum content;
  
  if((dbf=gdbm_open(options.mapname, 0, GDBM_READER, 0644, 0))==NULL){
    fprintf(
      stderr, 
      "makegdbm_undo: gdbm_open: %s: %s\n", 
      gdbm_strerror(gdbm_errno), 
      strerror(errno)
    );
    exit(-1);
  }

  this_key=gdbm_firstkey(dbf);
  if(this_key.dptr==NULL){
    fprintf(stderr, "makegdbm: makegdbm_undo: no first key\n");
    gdbm_close(dbf);
    exit(0);
  }

  while(1){
    fwrite(this_key.dptr, 1, this_key.dsize, stdout);
    fwrite(":", 1, 2, stdout);
    content=gdbm_fetch(dbf,this_key);
    if(content.dptr!=NULL){
      fwrite(content.dptr, 1, content.dsize, stdout);
    }
    fwrite("\n", 1, 2, stdout);

    next_key=gdbm_nextkey(dbf,this_key);
    if(next_key.dptr==NULL){
      break;
    }
    free(this_key.dptr);
    this_key=next_key;
  }
    
  gdbm_close(dbf);
 } 
