/**********************************************************************
 * pam.h                                                     March 1999
 * Horms                                             horms@verge.net.au
 *
 * Authenticate a user using pam
 *
 * Taken from the pam programming guide
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

#ifndef DO_PAM
#define DO_PAM


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WITH_PAM_SUPPORT

#ifdef HAVE_SECURITY_PAM_MISC_H
#include <security/pam_misc.h>
#endif /* HAVE_SECURITY_PAM_MISC_H */

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif /* HAVE_SECURITY_PAM_APPL_H */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SERVICE_NAME "perdition"
#define EX_PAM_ERROR -1

#include "log.h"

int do_pam_authentication(
  pam_handle_t *pamh,
  const char *user,
  const char *pass
);

int perdition_conv(
  int num_msg,
  const struct pam_message **msgm,
  struct pam_response **response,
  void *appdata_ptr
);
int do_pam_end(pam_handle_t *pamh, int default_return);

#endif  /*DO_PAM*/

#endif /* WITH_PAM_SUPPORT */
