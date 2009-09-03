/**********************************************************************
 * perditiondb_cdb.c                                     December 1999
 * Horms                                             horms@verge.net.au
 *
 * Access a cdb(3) database
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

#include "perditiondb_cdb.h"

#ifdef DMALLOC
#include <dmalloc.h>
#endif


/**********************************************************************
 * dbserver_get
 * Read the server (value) from a cdb map given the user (key)
 * pre: key_str: Key as a null terminated string
 *      options_str: Options string.
 *                   Ignored if NULL
 *                   Used as the map to open otherwise
 *      str_return: value is returned here
 *      len_return: length of value is returned here
 * post: The str_key is looked up in the cdb map and the
 *       corresponding value is returned in str_return and len_return.
 * return:  0 on success
 *         -1 on file access error
 *         -2 if key cannot be found in map
 *         -3 on other error
 **********************************************************************/

int dbserver_get(const char *key_str, const char *options_str, char **str_return, int *len_return) {

    int fd;
    int ret = -2; /* Presume key not found */

    /* Open a file handle on the CDB file */
    if((fd = open((options_str==NULL)?PERDITIONDB_CDB_DEFAULT_MAPNAME:(char *)options_str, O_RDONLY)) == -1) {
        /* File access error */
        return(-1);
    }

    /* Attempt to find the key in the file */
    if(cdb_seek(fd, (char *)key_str, strlen((char *)key_str), (int *)len_return) > 0) {

        char * str_value;

        /* Allocate memory for the result string and initialise it */
        str_value = (char *)malloc((*len_return + 1));
        memset(str_value, 0, (*len_return + 1));

        /* Read the value from the point found by seek. */
        cdb_bread(fd, str_value, *len_return);

        /* Stick a null terminator at the end of the string */
        str_value[*len_return] = '\0';

        /* Set string return value */
        *str_return = str_value;

        /* Set successful function return value */
        ret = 0;
    }

    /* Close and return */
    close(fd);
    return(ret);
}
