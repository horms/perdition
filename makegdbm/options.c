/**********************************************************************
 * options.c                                                   May 1999
 * Horms                                             horms@vergenet.net
 *
 * Parse command line arguments
 * Code based on man getopt(3), later translated to popt.
 * Some code based on man popt(3)
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

#include "options.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * makegdbm_options
 * parse command line arguments
 **********************************************************************/

makegdbm_options_t makegdbm_options(int argc, char **argv){
  int c=0;
  char *optarg;
  poptContext context;
  makegdbm_options_t opt;

  static struct poptOption options[] =
  {
    {"help",  'h', POPT_ARG_NONE, NULL, 'h'},
    {"undo",  'u', POPT_ARG_NONE, NULL, 'u'},
    {"jain",  'j', POPT_ARG_NONE, NULL, 'j'},
    {"jane",  'j', POPT_ARG_NONE, NULL, 'j'}, 
    {"jayne", 'j', POPT_ARG_NONE, NULL, 'j'},
    {NULL,    0,   0,             NULL, 0  }
  };


  /*Defaults*/
  opt.undo=0;

  if(argc==0 || argv==NULL) return(opt);

  context= poptGetContext("perdition", argc, (const char **)argv, options, 0);

  while ((c=poptGetNextOpt(context)) >= 0){
    optarg=(char *)poptGetOptArg(context);
    switch (c){
      case 'h':
        usage(0);
        break;
      case 'u':
        opt.undo=1;
        break;
      }
  }

  if (c < -1) {
    fprintf(
      stderr, 
      "options: %s: %s\n",
      poptBadOption(context, POPT_BADOPTION_NOALIAS),
      poptStrerror(c)
    );
  }
  
  opt.mapname = (char *)poptGetArg(context);
  if((opt.mapname == NULL) || !(poptPeekArg(context) == NULL)){
    usage(-1);
  }

  return(opt);
}


/**********************************************************************
 * usage
 * Display usage information and exit
 * Prints to stdout if exit_status=0, stderr otherwise
 **********************************************************************/

void usage(int exit_status){
  FILE *stream;

  if(exit_status!=0){
     stream=stderr;
  }
  else{
     stream=stdout;
  }

    
  fprintf(
    stream, 
    "Usage: makegdbm [options] gdbmname\n"
    "   options: -h, --help: print this message\n"
    "            -u, --undo: print content of database file, one entry a line\n"
  );

  exit(exit_status);
}
