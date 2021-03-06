/**********************************************************************
 * setproctitle.c                                              May 2001
 * Horms                                             horms@verge.net.au
 *
 * The code in this file, setproctitle.c is heavily based on code from
 * proftpd, please see the licensing information below.
 *
 * Code to portably change the title of a programme as displayed
 * by ps(1).
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

/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 *  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

#define PF_ARGV_NONE            0
#define PF_ARGV_NEW             1
#define PF_ARGV_WRITEABLE       2
#define PF_ARGV_PSTAT           3
#define PF_ARGV_PSSTRINGS       4

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
#	include <pstat.h>
#endif

#include "setproctitle.h"

static char **Argv = NULL;
static char *LastArgv = NULL;
extern char **environ;

#ifdef HAVE___PROGNAME
  extern char *__progname, *__progname_full;
#endif /* HAVE___PROGNAME */

void init_set_proc_title(int argc, char *argv[], char *envp[])
{
  int i, envpsize;
  char **p;
  
  /* Move the environment so setproctitle can use the space.
   */
  for(i = envpsize = 0; envp[i] != NULL; i++)
    envpsize += strlen(envp[i]) + 1;
  
  if((p = (char **) malloc((i + 1) * sizeof(char *))) != NULL ) {
    environ = p;

    for(i = 0; envp[i] != NULL; i++) {
      if((environ[i] = malloc(strlen(envp[i]) + 1)) != NULL)
	strcpy(environ[i], envp[i]);
    }
    
    environ[i] = NULL;
  }
  
  Argv = argv;
  
  for(i = 0; i < argc; i++) {
    if(!i || (LastArgv + 1 == argv[i]))
      LastArgv = argv[i] + strlen(argv[i]);
  }
  
  for(i = 0; envp[i] != NULL; i++) {
    if((LastArgv + 1) == envp[i])
      LastArgv = envp[i] + strlen(envp[i]);
  }
  
#ifdef HAVE___PROGNAME
  /* Set the __progname and __progname_full variables so glibc and company don't
   * go nuts. - MacGyver
   */
  __progname = strdup(get_progname(argv[0]));
  __progname_full = strdup(argv[0]);
#endif /* HAVE___PROGNAME */
  
#if 0
  /* Save argument/environment globals for use by set_proc_title */

  Argv = argv;
  while(*envp)
    envp++;

  LastArgv = envp[-1] + strlen(envp[-1]);
#endif
}    

void set_proc_title(const char *fmt,...)
{
  va_list msg;
  static char statbuf[BUFSIZ];
  
#ifndef HAVE_SETPROCTITLE
#if PF_ARGV_TYPE == PF_ARGV_PSTAT
   union pstun pst;
#endif /* PF_ARGV_PSTAT */
  int i;
#if PF_ARGV_TYPE == PF_ARGV_WRITEABLE
  int maxlen = (LastArgv - Argv[0]) - 2;
  char *p;
#endif
#endif /* HAVE_SETPROCTITLE */

  va_start(msg,fmt);

  memset(statbuf, 0, sizeof(statbuf));
  vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

#ifdef HAVE_SETPROCTITLE
  /* On systems with setproctitle(), v*printf are used on the arguments.
   * Prevent any possible format attacks.
   */
  setproctitle("%s", statbuf);
#endif /* HAVE_SETPROCTITLE */

  va_end(msg);
  
#ifdef HAVE_SETPROCTITLE
  return;
#else
  i = strlen(statbuf);

#if PF_ARGV_TYPE == PF_ARGV_NEW
  /* We can just replace argv[] arguments.  Nice and easy.
   */
  Argv[0] = statbuf;
  Argv[1] = NULL;
#endif /* PF_ARGV_NEW */

#if PF_ARGV_TYPE == PF_ARGV_WRITEABLE
  /* We can overwrite individual argv[] arguments.  Semi-nice.
   */
  snprintf(Argv[0], maxlen, "%s", statbuf);
  p = &Argv[0][i];
  
  while(p < LastArgv)
    *p++ = '\0';
  Argv[1] = NULL;
#endif /* PF_ARGV_WRITEABLE */

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
  pst.pst_command = statbuf;
  pstat(PSTAT_SETCMD, pst, i, 0, 0);
#endif /* PF_ARGV_PSTAT */

#if PF_ARGV_TYPE == PF_ARGV_PSSTRINGS
  PS_STRINGS->ps_nargvstr = 1;
  PS_STRINGS->ps_argvstr = statbuf;
#endif /* PF_ARGV_PSSTRINGS */

#endif /* HAVE_SETPROCTITLE */
}


const char *
get_progname(const char *argv_0)
{
	const char *progname;

	progname = strrchr(argv_0, '/');
	if (progname)
	   	return progname+1;

	return argv_0;
}
