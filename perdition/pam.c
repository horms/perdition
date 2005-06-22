/**********************************************************************
 * pam.c                                                     March 1999
 * Horms                                             horms@verge.net.au
 *
 * Authenticate a user using pam
 *
 * Taken from the pam programming guide
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "pam.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


#ifdef WITH_PAM_SUPPORT

int pam_retval;
struct pam_conv conv_struct={perdition_conv, NULL};

int perdition_conv(
  int num_msg,
  const struct pam_message **msgm,
  struct pam_response **response,
  void *appdata_ptr
){
  char *pass;

  extern int errno;

  if((
    *response=(struct pam_response *)malloc(sizeof(struct pam_response))
  )==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("malloc");
    return(PAM_CONV_ERR);
  }

  (*response)->resp_retcode=0;

  if((char *)appdata_ptr==NULL){
    pass=NULL;
  }
  else if((pass=strdup((char *)appdata_ptr))==NULL){
    VANESSA_LOGGER_DEBUG_ERRNO("strdup");
    return(PAM_CONV_ERR);
  }

  (*response)->resp=pass;
  return(PAM_SUCCESS);
}

int do_pam_authentication(
  pam_handle_t *pamh, 
  const char *user,
  const char *pass
){
  conv_struct.appdata_ptr=(void *)pass;
  pam_retval = pam_set_item(pamh, PAM_CONV, (void *) &conv_struct);
  if (pam_retval != PAM_SUCCESS) {
    VANESSA_LOGGER_DEBUG_UNSAFE(
      "pam_set_item: PAM_CONV: %s", 
      pam_strerror(pamh, pam_retval)
    );
    return(-1);
  }

  pam_retval = pam_set_item(pamh, PAM_USER, user);
  if (pam_retval != PAM_SUCCESS) {
    VANESSA_LOGGER_DEBUG_UNSAFE("pam_set_item: %s", pam_strerror(pamh, pam_retval));
    return(-1);
  }

  pam_retval = pam_authenticate(pamh, 0);  /* is user really user? */
  if (pam_retval != PAM_SUCCESS) {
    VANESSA_LOGGER_DEBUG_UNSAFE("pam_authenticate: %s", 
      pam_strerror(pamh, pam_retval));
    return(-1);
  }

  pam_retval = pam_acct_mgmt(pamh, 0);     /* permitted access? */
  if (pam_retval != PAM_SUCCESS) {
    VANESSA_LOGGER_DEBUG_UNSAFE(
      "do_pam_authentication: pam_acct_mgmt: %s", 
      pam_strerror(pamh, pam_retval)
    );
    return(-1);
  }

  return (0);
}

int do_pam_end(pam_handle_t *pamh, int default_return){
  pam_retval=pam_end(pamh,pam_retval);  /* close Linux-PAM */
  if (pam_retval != PAM_SUCCESS) {   /* close Linux-PAM */
    VANESSA_LOGGER_DEBUG_UNSAFE("do_pam_end: pam_end: %s", 
      pam_strerror(pamh, pam_retval));
    pamh = NULL;
    return(EX_PAM_ERROR);
  }
  return(default_return);
}
#endif
