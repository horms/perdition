/**********************************************************************
 * str.h                                                 September 1999
 * Horms                                             horms@vergenet.net
 *
 * Various string handling functions
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

#ifndef _PERDITION_STR_H
#define _PERDITION_STR_H

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/uio.h>
#include <vanessa_socket.h>

#include "perdition_types.h"
#include "io.h"

#define STR_NULL "(null)"

/*Flags for str_write */
#define WRITE_STR_NO_CLLF     0x1	/*Append a CLLF */
#define STR_WRITE_BUF_LEN     MAX_LINE_LENGTH


/**********************************************************************
 * strrstr
 * Find the last occurrence of substring needle in the string
 * haystack
 * pre: haystack: haystack to search
 *      needle: needle to search for
 * post: none
 * return: NULL if needle is not in haystack
 *         haystack if needle is NULL
 *         last occurance of needle in haystack
 **********************************************************************/

char *strrstr(const char *haystack, const char *needle);


#define STRSTR_FORWARD 0x1
#define STRSTR_REVERSE 0x2

/**********************************************************************
 * strstr_sw
 * Wrapper for strstr() and strrstr()
 * pre: haystack: haystack to pass to strstr or strrstr
 *      needle: needle to pass to strstr or strrstr
 *      direction: STRSTR_FORWARD to call strstr()
 *                 STRSTR_REVERSE to call strrstr()
 * post: none
 * return: NULL if needle is not in haystack
 *         haystack if needle is NULL
 *         last occurance of needle in haystack
 **********************************************************************/

char *strstr_sw(const char *haystack, const char *needle, int direction);


/**********************************************************************
 * strn_to_str
 * Convert a non null terminated string into a null terminated string
 * pre: string:  source string
 *      n:    bytes from string to put in allocated string
 * post: a new string is allocated to hold n bytes of string and 
 *       a teminating '\0'
 * return: NULL on error
 *         allocated string otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

char *strn_to_str(const char *string, const size_t n);


/**********************************************************************
 * str_write
 * write strings to fd by puting them into tokens and
 * printing the tokens
 * if !(flag&WRITE_STR_NO_CLLF)
 *   append a CRLF to the output (intput strings should not end in a CRLF)
 * 
 * pre: io: io_t to write to
 *      flag: If WRITE_STR_NO_CLLF then CLLF is appended to output
 *      nargs: number of arguments after format string.
 *             This should help to rule out format string bugs.
 *      fmt: format for output, as per vsnprintf()
 *      ...: strings
 * post strings are printed to fd
 * return: -1 on error
 *         0 otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

int str_write(io_t * io, const flag_t flag, const size_t nargs,
	      const char *fmt, ...);


/**********************************************************************
 * str_cat
 * Concatenate strings together
 * pre: nostring: number of strings
 *      ...: strings to concatenate together
 * post: a string is allocated to store the concatenation of the strings
 * return: NULL on error
 *         concatenated string otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

char *str_cat(const int nostring, ...);


/**********************************************************************
 * str_free
 * Free a string if it is not NULL
 * pre: string: string to free
 * post: string is freed if it is not NULL
 * return: none
 *
 * Not 8 bit clean
 **********************************************************************/

#define str_free(string) \
  if(string!=NULL){ \
    free(string); \
    string=NULL; \
  }


/**********************************************************************
 * str_null_safe
 * return a pinter to a sane string if string is NULL
 * So we can print NULL strings safely
 * pre: string: string to test
 * return: string is if it is not NULL
 *         STR_NULL otherwise
 *
 * 8 bit clean
 **********************************************************************/

#define str_null_safe(string) \
  (string==NULL)?STR_NULL:string


/**********************************************************************
 * strn_tolower
 * 
 * pre: str: String to change charaters of to lower case
 *      count: Number of characters in string to change
 * post: count characters in str, from the begining of str, 
 *       are converted to lowercase using tolower(3).
 * return: str with characters converted to lowercase
 *
 * Not 8 bit clean
 **********************************************************************/

char *strn_tolower(char *str, size_t count);


/**********************************************************************
 * strn_tolower
 * 
 * pre: str: String to change charaters of to lower case
 *      count: Number of characters in string to change
 * post: count characters in str, from the begining of str, 
 *       are converted to lowercase using tolower(3).
 * return: str with characters converted to lowercase
 *
 * Not 8 bit clean
 **********************************************************************/

#define str_tolower(str) strn_tolower(str, strlen(str))


/**********************************************************************
 * strn_toupper
 * 
 * pre: str: String to change charaters of to upper case
 *      count: Number of characters in string to change
 * post: count characters in str, from the begining of str, 
 *       are converted to uppercase using toupper(3).
 * return: str with characters converted to uppercase
 *
 * Not 8 bit clean
 **********************************************************************/

char *strn_toupper(char *str, size_t count);


/**********************************************************************
 * strn_toupper
 * 
 * pre: str: String to change charaters of to upper case
 *      count: Number of characters in string to change
 * post: count characters in str, from the begining of str, 
 *       are converted to uppercase using toupper(3).
 * return: str with characters converted to uppercase
 *
 * Not 8 bit clean
 **********************************************************************/

#define str_toupper(str) strn_toupper(str, strlen(str))


/**********************************************************************
 * str_basename
 * Find the filename of a fully qualified path to a file
 * pre: filename: name of file to find basename of
 * post: basename of filename is returned
 * return: NULL if filename is NULL
 *         pointer within filename pointing to basename of filename
 *
 * Not 8 bit clean
 **********************************************************************/

const char *str_basename(const char *filename);


/**********************************************************************
 * str_delete_substring
 * Remove a needles from a haystack.
 * It is not an error if there are no needles in the haystack.
 * pre: haystack: String to remove needles from.
 *      needle: Needle to remove from haystack
 *      delimiter: Delimiter that may follow the needle.
 * post: Needles, and a following delimiter if present, will be
 *       removed from the haystack.
 *       Note that a needle must either be followed by a delimiter
 *       or be at the end of the haystack to be removed.
 * return: New haystack. This should be freed by the caller.
 *         NULL on error
 **********************************************************************/

char *str_delete_substring(const char *haystack, const char *needle,
			   const char *delimiter);


/**********************************************************************
 * str_append_substring_if_missing
 * Append a delimiter and needle to the haystack, if the haystack
 * does not contain a needle that is either followed by
 * delimiter or is at the end of the haystack.
 * pre: haystack: String to add needle to.
 *      needle: Needle to add to haystack
 *      delimiter: Delimiter.
 * post: A copy of the haystack is created.
 *       If the needle isn't present in the original haystack, it is added.
 * return: New haystack. This should be freed by the caller.
 *         NULL on error
 **********************************************************************/

char *str_append_substring_if_missing(const char *haystack,
				      const char *needle,
				      const char *delimiter);


/**********************************************************************
 * str_rolling32
 * Produce a rolling 32 bit checksum for a buffer
 * pre: buf: buffer to checksum
 *      len: number of bytes to checksum
 * post: Rolling 32 bit checksum is calculated
 * return: checksum
 **********************************************************************/

uint32 str_rolling32(unsigned char *buf, size_t len);


#endif				/* _PERDITION_STR_H */
