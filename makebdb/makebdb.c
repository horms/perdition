/**********************************************************************
 * makebdb.c                                                   May 2002
 * ChrisS                                              chriss@pipex.net
 *
 * Create a bdb file from a : delimited flat file read from stdin
 * Based (very heavily) on makegdbm.c by Horms
 *
 * perdition
 * Mail retrieval proxy server
 * Copyright (C) 1999-2003  Horms
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <db.h>

#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


extern int errno;

#define MAX_LINE_LENGTH 4096
#define FIELD_DELIMITER ':'

void makebdb_new(const makebdb_options_t options);
void makebdb_undo(const makebdb_options_t options);

int main(int argc, char **argv){
  makebdb_options_t options;

  options=makebdb_options(argc, argv);


  if(options.undo){
    makebdb_undo(options);
  }
  else{
    makebdb_new(options);
  }

  return(0);
}
  

/**********************************************************************
 * makebdb_new
 * Create a new bdb file from a flat file read from stdin
 * pre: options: options structure specifying what to do
 * post: bdb file created and populated
 **********************************************************************/

void makebdb_new(const makebdb_options_t options){
  DB *dbp;
  DBT key;
  DBT content;
  int ret;
  int i;
  char line[MAX_LINE_LENGTH];
  int status;
  int blank;
  int lineno;

  if ((ret=db_create(&dbp, NULL, 0)) != 0) {
    fprintf(stderr,"makebdb_new: db_create: %s\n",db_strerror(ret));
    exit(-1);
  }
  if ((ret=dbp->open(
    dbp,
#ifdef HAVE_BDB_4_1
    NULL,
#endif
    options.mapname,
    NULL,
    DB_HASH,
    DB_CREATE,
    0644
  )) != 0) {
    fprintf(stderr,"makebdb_new: DB->open: %s\n",db_strerror(ret));
    exit(-1);
  }

  /*Warning: This loop contains some of the worst code ever written*/
  memset(&key, 0, sizeof(key));
  memset(&content, 0, sizeof(content));
  status=0;
  lineno=0;
  while(fgets(line, MAX_LINE_LENGTH, stdin)!=NULL){
    blank=1;
    key.data=line;
    key.size=-1;
    content.size=-1;
    for(i=0;i<MAX_LINE_LENGTH;i++){
      if(blank && *(line+i)!=' ' && *(line+i)!='\t'&& *(line+i)!='\n'){
        blank=0;
      }
      if(key.size==-1 && *(line+i)==FIELD_DELIMITER){
        key.size=i;
        content.data=line+i+1;
        continue;
      }
      if(content.size==-1 && *(line+i)=='\n'){
        content.size=i-key.size-1;
        lineno++;
        break;
      }
    }
    fflush(NULL);
    if(!blank && !status && (key.size<1 || content.size<1)){
      status=1;
    }
    if(status){
      if(*(line+i)=='\n'){
        fprintf(stderr, "makebdb: invalid input on line: %d \n", lineno);
        status=0;
      }
      continue;
    }

    if(blank){
      continue;
    }
    if ((ret = dbp->put(dbp, NULL, &key, &content, DB_NOOVERWRITE))!=0){
      *((char *)key.data+key.size)='\0';
      fprintf(stderr, "makebdb: %s (key: %s)\n",db_strerror(ret),
		      (char *)key.data);
    }

  }

  dbp->close(dbp, 0);
}


/**********************************************************************
 * makebdb_undo
 * print out a : delimited flat file to stdout of a bdb file
 * pre: options: options structure sepcifying what to do
 * post: glat file output to stdout
 **********************************************************************/

void makebdb_undo(makebdb_options_t options){
  DB *dbp;
  DBC *dbcp;
  DBT key;
  DBT content;
  int ret;
  
  if ((ret=db_create(&dbp, NULL, 0)) != 0) {
    fprintf(stderr,"makebdb_undo: db_create: %s\n",db_strerror(ret));
    exit(-1);
  }
  if ((ret=dbp->open(
    dbp,
#ifdef HAVE_BDB_4_1
    NULL,
#endif
    options.mapname,
    NULL,
    DB_HASH,
    DB_RDONLY,
    0644
  )) != 0) {
    fprintf(stderr,"makebdb_undo: DB->open: %s\n",db_strerror(ret));
    exit(-1);
  }

  if ((ret = dbp->cursor(dbp, NULL, &dbcp, 0))!=0) {
    fprintf(stderr,"makebdb_undo: DB->cursor: %s\n",db_strerror(ret));
    exit(-1);
  };

  memset(&key, 0, sizeof(key));
  memset(&content, 0, sizeof(content));

  while((ret=dbcp->c_get(dbcp,&key,&content,DB_NEXT))==0)
  {
    printf("%*s:%*s\n", key.size, (char *)key.data, 
		    content.size, (char *) content.data);
  }
  if(ret != DB_NOTFOUND){
    fprintf(stderr,"makebdb_undo: DBcursor->get: %s\n",db_strerror(ret));
  }

  dbcp->c_close(dbcp);
  dbp->close(dbp, 0);
} 
