/**********************************************************************
 * options.h                                                   May 1999
 * Horms                                             horms@vergenet.net
 *
 * Parse command line arguments
 * Code based on man getopt(3), later translated to popt.
 * Some code based on man popt(3)
 *
 *
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

#ifndef ARGUMENTS_BERT
#define ARGUMENTS_BERT

#include <stdio.h>
#include <string.h>
#include <gdbm.h>
#include <popt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

extern gdbm_error gdbm_errno;
extern char *gdbm_version;

#include "jain.h"

#define COPYRIGHT \
  "(c) 1999 Horms <horms@vergenet.net>\nReleased under the GNU GPL\n"

typedef struct {
  char *mapname;
  int undo;
} makegdbm_options_t; 

extern char *optarg;
extern int optind, opterr, optopt;

makegdbm_options_t makegdbm_options(int argc, char **argv);
void usage(int exit_status);
void version(void);

#endif
