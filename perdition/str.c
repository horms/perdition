/**********************************************************************
 * str.c                                                    August 1999
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
 **********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "io.h"
#include "str.h"
#include "options.h"
#include "perdition_types.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#ifdef HAVE_PARSE_PRINTF_FORMAT
#include <printf.h>
#endif
#include <sys/uio.h>
#include <vanessa_socket.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif


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

char *strrstr(const char *haystack, const char *needle)
{
	size_t haystack_len;
	size_t needle_len;
	const char *p;

	if(!*haystack) {
		return(NULL);
	}
	if(!*needle) {
		return((char *) haystack);
	}

	haystack_len = strlen(haystack);
	needle_len = strlen(needle);
	if(haystack_len < needle_len) {
		return(NULL);
	}

	p = haystack + haystack_len - needle_len;
	for( ; p >= haystack ; p--) {
		if(strncmp(p, needle, needle_len) == 0) {
			return((char *) p);
		}
	}

	return(NULL);
}


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

char *strstr_sw(const char *haystack, const char *needle, int direction)
{
	if(direction == STRSTR_REVERSE) {
		return(strrstr(haystack, needle));
	}
	return(strstr(haystack, needle));

}


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

char *strn_to_str(const char *string, const size_t n)
{
	char *dest;

	if ((dest = (char *) malloc(n + 1)) == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc");
		return (NULL);
	}
	strncpy(dest, string, n);
	*(dest + n) = '\0';

	return (dest);
}


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

static char __str_write_buf[STR_WRITE_BUF_LEN];

static const char *__str_vwrite(io_t * io, const flag_t flag, 
		const size_t nargs, const char *fmt, va_list ap,
		int *bytes)
{
	int fmt_args;
#ifndef HAVE_PARSE_PRINT_FORMAT
	int place;
#endif				/* HAVE_PARSE_PRINT_FORMAT */

	/* Fast Path */
	if(!nargs && (flag & WRITE_STR_NO_CLLF)) {
		*bytes = strlen(fmt);
		return(fmt);
	}

	/* Slow Path */

#ifndef HAVE_PARSE_PRINT_FORMAT
	fmt_args = 0;
	for (place = 0; fmt[place] != '\0'; place++) {
		if (fmt[place] == '%')
			fmt[place + 1] == '%' ? place++ : fmt_args++;
	}
	if (fmt_args != nargs) {
#else				/* HAVE_PARSE_PRINT_FORMAT */
	if ((fmt_args = parse_printf_format(fmt, 0, NULL)) != nargs) {
#endif				/* HAVE_PARSE_PRINT_FORMAT */
		VANESSA_LOGGER_DEBUG_UNSAFE("nargs and fmt mismatch: "
				"%d args requested, %d args in format",
		     		nargs, fmt_args);
		return (NULL);
	}

	*bytes = vsnprintf(__str_write_buf, STR_WRITE_BUF_LEN - 2, fmt, ap);
	if(*bytes < 0) {
		VANESSA_LOGGER_DEBUG_ERRNO("vsnprintf");
		return (NULL);
	}

	/* Add carriage return,newline to output. */
	if (!(flag & WRITE_STR_NO_CLLF)) {
		memcpy(__str_write_buf + *bytes, "\r\n", 2);
		*bytes += 2;
	}

	return (__str_write_buf);
}


int str_vwrite(io_t * io, const flag_t flag, const size_t nargs,
	      const char *fmt, va_list ap)
{
	const char *str;
	int bytes = 0;

	extern options_t opt;

	str = __str_vwrite(io, flag, nargs, fmt, ap, &bytes);
	if(!str) {
		VANESSA_LOGGER_DEBUG("__str_vwrite");
		return(-1);
	}

	if (opt.connection_logging) {
		char *dump_str;

		dump_str = VANESSA_LOGGER_DUMP(str, bytes, 0);
		if (!dump_str) {
			VANESSA_LOGGER_DEBUG("VANESSA_LOGGER_DUMP");
			return (-1);
		}
		VANESSA_LOGGER_LOG_UNSAFE(LOG_DEBUG, "%s \"%s\"",
					  PERDITION_LOG_STR_SELF,
					  dump_str);
		free(dump_str);
	}

	/* Attempt one write system call and return an error if it
	   doesn't write all the bytes. */
	if (io_write(io, str, bytes) != bytes) {
		VANESSA_LOGGER_DEBUG_ERRNO("io_write");
		return (-1);
	}

	return (0);
}



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
	      const char *fmt, ...)
{
	int bytes;
	va_list ap;

	va_start(ap, fmt);
	bytes = str_vwrite(io, flag, nargs, fmt, ap);
	va_end(ap);

	if(bytes < 0) {
		VANESSA_LOGGER_DEBUG("str_vwrite");
		return(-1);
	}

	return(0);
}


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

char *str_cat(const int nostring, ...)
{
	va_list ap;
	char **string;
	char **current_string;
	char *dest;
	int length;
	int i;

	if (nostring < 1) {
		return (NULL);
	}

	if ((string = (char **) malloc(sizeof(char *) * nostring)) == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc 1");
		return (NULL);
	}

	current_string = string;
	length = 1;

	va_start(ap, nostring);
	for (i = 0; i < nostring; i++) {
		*current_string = va_arg(ap, char *);
		if (*current_string == NULL) {
			VANESSA_LOGGER_DEBUG("null string");
			free(string);
			return (NULL);
		}
		length += strlen(*current_string);
		current_string++;
	}
	va_end(ap);

	if ((dest = (char *) malloc(sizeof(char) * length)) == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("malloc 2");
		free(string);
		return (NULL);
	}

	current_string = string;
	strcpy(dest, *current_string++);
	for (i = 1; i < nostring; i++) {
		strcat(dest, *current_string++);
	}

	free(string);

	return (dest);
}


/**********************************************************************
 * str_free
 **********************************************************************/

#define str_free(string) \
  if(string!=NULL){ \
    free(string); \
    string=NULL; \
  }


/**********************************************************************
 * str_null_safe
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

char *strn_tolower(char *str, size_t count)
{
	char *current;

	for (current = str; count > 0; current++, count--) {
		*current = (char) tolower((int) *current);
	}

	return (str);
}


/**********************************************************************
 * strn_tolower
 * Macro defined elsewhere
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

char *strn_toupper(char *str, size_t count)
{
	char *current;

	for (current = str; count > 0; current++, count--) {
		*current = (char) toupper((int) *current);
	}

	return (str);
}


/**********************************************************************
 * strn_toupper
 * Macro defined elsewhere
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

const char *str_basename(const char *filename)
{
	char *result;

	if (filename == NULL) {
		return (NULL);
	}

	result = strrchr(filename, '/');

	return ((result == NULL) ? filename : result + 1);
}


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
			   const char *delimiter)
{
	size_t needle_len;
	size_t delimiter_len;
	char *start;
	char *end;
	char *prefix;
	char *new_haystack;

	needle_len = strlen(needle);
	delimiter_len = strlen(delimiter);

	new_haystack = strdup(haystack);
	if (new_haystack == NULL) {
		VANESSA_LOGGER_DEBUG_ERRNO("strdup");
		return (NULL);
	}

	start = new_haystack;
	while (1) {
		if ((start = strstr(start, needle)) == NULL) {
			break;
		}

		/* Is the needle at the beginning of the string or
		 * preceded by a delimiter. If not it is not a valid
		 * match */
		prefix = start - delimiter_len;
		if (start != new_haystack && (prefix < new_haystack ||
					      strncmp(prefix, delimiter,
						      delimiter_len))) {
			start += needle_len;
			continue;
		}

		/* Is the needle at the end of the string or
		 * followed by a delimiter. If not it is not a valid
		 * match */
		end = start + needle_len;
		if (*end != '\0' && strncmp(end, delimiter, delimiter_len)) {
			start += needle_len;
			continue;
		}

		/* leading delimiter */
		if (start != '\0') {
			start = prefix;
		}
		memmove(start, end, strlen(end) + 1);
	}

	return (new_haystack);
}


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
				      const char *delimiter)
{
	size_t n_len;
	size_t d_len;
	const char *cursor;
	const char *tmp;
	char *new_haystack = NULL;
	int found = 0;

	n_len = strlen(needle);
	d_len = strlen(delimiter);

	cursor = haystack;
	while (1) {
		if ((cursor = strstr(cursor, needle)) == NULL) {
			break;
		}

		/* Is the needle at the beginning of the string or
		 * preceded by a delimiter. If not it is not a valid
		 * match */
		tmp = cursor - d_len;
		if (cursor != new_haystack && (tmp < new_haystack ||
					       strncmp(tmp, delimiter,
						       d_len))) {
			cursor += n_len;
			continue;
		}

		/* Is the needle at the end of the string or
		 * followed by a delimiter. If not it is not a valid
		 * match */
		tmp = cursor + n_len;
		if (*tmp != '\0' && strncmp(tmp, delimiter, d_len)) {
			cursor += n_len;
			continue;
		}

		found = 1;
		break;
	}

	if (found) {
		new_haystack = strdup(haystack);
		if (new_haystack == NULL) {
			VANESSA_LOGGER_DEBUG_ERRNO("strdup");
			return (NULL);
		}
		return (new_haystack);
	}

	new_haystack = str_cat(3, haystack, delimiter, needle);
	if (new_haystack == NULL) {
		VANESSA_LOGGER_DEBUG("str_cat");
		return (NULL);
	}

	return (new_haystack);
}


/**********************************************************************
 * str_rolling32
 * Produce a rolling 32 bit checksum for a buffer
 * pre: buf: buffer to checksum
 *      len: number of bytes to checksum
 * post: Rolling 32 bit checksum is calculated
 * return: checksum
 **********************************************************************/

uint32 str_rolling32(unsigned char *buf, size_t len) {
	size_t i;
	uint32 csum;

	csum = 0;
	for(i = 0; i < len - 1; i++) {
		csum += *(buf+i);
	}

	return(csum);
}


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

char *str_replace(char *str, size_t n, ...) 
{
	va_list ap;
	const char *match;
	const char *subst;
	size_t match_len;
	size_t subst_len;
	char *p;
	size_t offset;

	if(!n || n & 0x1) {
		VANESSA_LOGGER_DEBUG("Invalid n");
		return(NULL);
	}

	va_start(ap, n);
	while(n) {
		match = va_arg(ap, char *);
		subst = va_arg(ap, char *);

		match_len = strlen(match);
		subst_len = strlen(subst);

		p = str;
		while((p=strstr(p, match))) {
			if(subst_len > match_len) {
				offset = p - str;
				p = realloc(str, strlen(str) + 
						subst_len-match_len);
				if(!p) {
					VANESSA_LOGGER_DEBUG_ERRNO("realloc");
					free(str);
				}
				str = p;
				p = str + offset;
				memmove(p, p+match_len-subst_len,
					strlen(p+match_len-subst_len)+1);
			}
			else if (subst_len < match_len) {
				memmove(p, p+match_len-subst_len,
					strlen(p+match_len-subst_len)+1);
			}
			memcpy(p, subst, subst_len);
			p+=subst_len;
		}
		n-=2;
	}
	va_end(ap);

	return(str);
}

