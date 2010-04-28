/**********************************************************************
 * str.h                                                 September 1999
 * Horms                                             horms@verge.net.au
 *
 * Various string handling functions
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
 *         last occurrence of needle in haystack
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
 *         last occurrence of needle in haystack
 **********************************************************************/

char *strstr_sw(const char *haystack, const char *needle, int direction);


/**********************************************************************
 * strn_to_str
 * Convert a non null terminated string into a null terminated string
 * pre: string:  source string
 *      n:    bytes from string to put in allocated string
 * post: a new string is allocated to hold n bytes of string and 
 *       a terminating '\0'
 * return: NULL on error
 *         allocated string otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

char *strn_to_str(const char *string, const size_t n);


/**********************************************************************
 * str_vwrite
 * write strings to fd by putting them into tokens and
 * printing the tokens
 * if !(flag&WRITE_STR_NO_CLLF)
 *   append a CRLF to the output (input strings should not end in a CRLF)
 * 
 * pre: io: io_t to write to
 *      flag: If WRITE_STR_NO_CLLF then CLLF is appended to output
 *      nargs: number of arguments after format string.
 *             This should help to rule out format string bugs.
 *      fmt: format for output, as per vsnprintf()
 *      ap: strings
 * post strings are printed to fd
 * return: -1 on error
 *         0 otherwise
 *
 * Not 8 bit clean
 **********************************************************************/

int str_vwrite(io_t * io, const flag_t flag, const size_t nargs,
	      const char *fmt, va_list ap);


/**********************************************************************
 * str_write
 * write strings to fd by putting them into tokens and
 * printing the tokens
 * if !(flag&WRITE_STR_NO_CLLF)
 *   append a CRLF to the output (input strings should not end in a CRLF)
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
 * pre: str: String to change characters of to lower case
 *      count: Number of characters in string to change
 * post: count characters in str, from the beginning of str, 
 *       are converted to lowercase using tolower(3).
 * return: str with characters converted to lowercase
 *
 * Not 8 bit clean
 **********************************************************************/

char *strn_tolower(char *str, size_t count);


/**********************************************************************
 * strn_tolower
 * 
 * pre: str: String to change characters of to lower case
 *      count: Number of characters in string to change
 * post: count characters in str, from the beginning of str, 
 *       are converted to lowercase using tolower(3).
 * return: str with characters converted to lowercase
 *
 * Not 8 bit clean
 **********************************************************************/

#define str_tolower(str) strn_tolower(str, strlen(str))


/**********************************************************************
 * strn_toupper
 * 
 * pre: str: String to change characters of to upper case
 *      count: Number of characters in string to change
 * post: count characters in str, from the beginning of str, 
 *       are converted to uppercase using toupper(3).
 * return: str with characters converted to uppercase
 *
 * Not 8 bit clean
 **********************************************************************/

char *strn_toupper(char *str, size_t count);


/**********************************************************************
 * strn_toupper
 * 
 * pre: str: String to change characters of to upper case
 *      count: Number of characters in string to change
 * post: count characters in str, from the beginning of str, 
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


/**********************************************************************
 * str_replace
 * Replace elements of a string
 * pre: str: string to make substitutions in
 *      n: number of strings following
 *      ...: Pairs of strings. The first is the string to match.
 *           The second is the string to substitute it with
 * post: All instances of the match strings are replaced with 
 *       their corresponding substitution.
 *       The match/substitute pairs are processed in order.
 *       Str is processed from beginning to end for each match/substitute
 *       pair.
 *       str may be realloced if more space is needed
 * return: New string. May be the same as the str parameter.
 *         If not str will have been freed.
 *         NULL on error, in which case str is freed.
 **********************************************************************/

char *str_replace(char *str, size_t n, ...);

/**********************************************************************
 * strcasestring
 * Find the first occurrence of string in a string, case insensitively
 * pre: haystack: string to search in
 *      needle: string to search for
 * return: pointer to the first occurrence of needle
 *         NULL on error
 *
 * Note: returns a const char* rather than a char * like strstr().
 *       This seems more logical given the type of the inputs.
 *
 *       strcasestr() exists in gcc (and returns char *) but this
 *       is a GNU extension. As an implementation is needed for when
 *       perdition is compiled against other libcs, it may as be used all
 *       the time.
 **********************************************************************/

const char *strcasestr(const char *haystack, const char *needle);

/**********************************************************************
 * strcasedelimword
 * Find the first occurrence of a word in a string
 * That is, find a needle in a haystack and make sure that;
 * a) the needle is either at the beginning of the haystack or
 *    preceded by a character present in delim and;
 * b) the needle is either at the end of the haystack or
 *     followed by a character present in delim
 * pre: haystack: string to search in
 *      needle: string to search for
 *      delim: list of delimiter characters (case sensitive)
 * return: pointer to the first occurrence of needle
 *         NULL on error
 *
 * Note: returns a const char* rather than a char * like strstr().
 *       This seems more logical given the type of the inputs.
 **********************************************************************/

const char *strcasedelimword(const char *haystack, const char *needle,
			     const char *delim);

/**********************************************************************
 * strcaseword
 * Find the first occurrence of a word in a string
 * That is, find a needle in a haystack and make sure that;
 * a) the needle is either at the beginning of the haystack or
 *    preceded by a space and;
 * b) the needle is either at the end of the haystack or
 *     followed by a space
 * pre: haystack: string to search in
 *      needle: string to search for
 * return: pointer to the first occurrence of needle
 *         NULL on error
 *
 * Note: returns a const char* rather than a char * like strstr().
 *       This seems more logical given the type of the inputs.
 **********************************************************************/

static inline const char *
strcaseword(const char *haystack, const char *needle)
{
	return strcasedelimword(haystack, needle, " ");
}

#endif				/* _PERDITION_STR_H */
