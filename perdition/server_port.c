/**********************************************************************
 * server_port.c                                               May 1999
 * Horms                                             horms@vergenet.net
 *
 * Data type for handling server/port pairs
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

#include "server_port.h"


/**********************************************************************
 * server_port_create
 * Create an empty server_port structure
 **********************************************************************/

server_port_t *server_port_create (void){
  server_port_t *server_port;

  if((server_port=(server_port_t *)malloc(sizeof(server_port_t)))==NULL){
    PERDITION_LOG(LOG_DEBUG, "server_port_create: malloc: %s", strerror(errno));
    return(NULL);
  }
  server_port->servername=NULL;
  server_port->port=NULL;
  return(server_port);
}


/**********************************************************************
 * server_port_assign
 * Assign values to a server_port_structure
 **********************************************************************/

void server_port_assign(
  server_port_t *server_port, 
  char *servername, 
  char *port
){
  server_port->servername=servername;
  server_port->port=port;
}


/**********************************************************************
 * server_port_strn_assign
 * Assign the data in a sting, to a port structure
 * pre: str should be of the form 
 *        <servername>:<port>   or
 *        <servername>:         or
 *        <servername>
 *      len: length of str
 * post: <servername> is assigned to server_port.servername
 *       <port> is assigned to server_port.port
 *
 * In the case of the last two formats for str, 
 * server_port_t.port will be set to NULL
 *
 * Altenatively if len==0 both servername and port in
 * the resulting server_port_t will be NULL
 **********************************************************************/

server_port_t *server_port_strn_assign(
  server_port_t *server_port, 
  const char *str,
  const int len
){
  int delimiter;

  server_port_unassign(server_port);

  if(len==0){
    return(server_port);
  }

  for(delimiter=0;delimiter<len;delimiter++){
    if(*(str+delimiter)==SERVER_PORT_DELIMITER){
      break;
    }
  }

  if(delimiter!=len){
    if((server_port->port=strn_to_str(str+delimiter+1,len-delimiter-1))==NULL){
      PERDITION_LOG( LOG_DEBUG, "server_port_strn_assign: strn_to_str port");
      free(server_port);
      return(NULL);
    }
  }

  if((server_port->servername=strn_to_str(str, delimiter))==NULL){
    PERDITION_LOG(LOG_DEBUG, "server_port_strn_assign: strn_to_str servername");
    free(server_port->port);
    free(server_port);
    return(NULL);
  }

  return(server_port);
}


/**********************************************************************
 * server_port_unassign
 * Unassign any values but do not free their memory.
 **********************************************************************/

void server_port_unassign(server_port_t *server_port){
  server_port_assign(server_port, (char *)NULL, (char *)NULL);
}


/**********************************************************************
 * server_port_unassign
 * Free a server_port structure and free any non NULL elements.
 *
 * If you don't want to free the memory  of elements you should
 * use server_port_unassign(server_port);
 * first.
 **********************************************************************/

void server_port_destroy(server_port_t *server_port){
  if(server_port==NULL){
    return;
  }

  if(server_port->servername!=NULL){
    free(server_port->servername);
  }
  if(server_port->port!=NULL){
    free(server_port->port);
  }

  free(server_port);
}


/**********************************************************************
 * server_port_get_port
 * Get the port from a server_port structure
 **********************************************************************/

char * server_port_get_port(const server_port_t *server_port){
  return(server_port->port);
}


/**********************************************************************
 * server_port_get_servername
 * Get the servername from a server_port_structure
 **********************************************************************/

char * server_port_get_servername(const server_port_t *server_port){
  return(server_port->servername);
}


/**********************************************************************
 * server_port_display
 * Render a server port structure to a string with the 
 * server and port separated by SERVER_PORT_DELIMITER
 * Analogous to strcpy for strings
 * pre: dest: allocated string to render server_port to
 *      server_port: server_port_t to render
 * post: server_port is rendered to dest with a terminateing '\0'
 *       nothing if server_port is NULL
 **********************************************************************/

void server_port_display(char *dest, const server_port_t *server_port){
  size_t len=0;
 
  if(server_port==NULL){
    return;
  }
  if(server_port->servername!=NULL){
    strcpy(dest, server_port->servername);
    len=strlen(server_port->servername);
  }
  if(server_port->port!=NULL){
    *(dest+len++)=SERVER_PORT_DELIMITER;
    strcpy(dest+len, server_port->port);
  }
}


/**********************************************************************
 * server_port_length
 * Report the rendered length of a server_port not including
 * the trailing '\0'
 * Analogous to strlen for strings
 * pre: src: the server port to find the rendered length of
 * return: rendered length of the server_port
 *         0 if server_port is NULL
 **********************************************************************/

size_t server_port_length(server_port_t *src){
  if(src==NULL){
    return(0);
  }
  else{
    return(
      ((src->servername==NULL)?0:strlen(src->servername)) + 
      ((src->port==NULL)?0:(strlen(src->port)+1))
    );
  }
}


/**********************************************************************
 * server_port_dup
 * Duplicate a server_port
 * pre: src: server_port to duplicate
 * post: src is duplicted
 * return: copy of server_port
 *         NULL on error or of src is NULL
 **********************************************************************/

server_port_t *server_port_dup(server_port_t *src){
  server_port_t *dest;

  if(src==NULL || (dest=server_port_create())==NULL){
    return(NULL);
  }
  dest->servername=(src->servername==NULL)?NULL:strdup(src->servername);
  dest->port=(src->port==NULL)?NULL:strdup(src->port);
  return(dest);
}
