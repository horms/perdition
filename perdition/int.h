/**********************************************************************
 * int.h                                                     April 2001
 * Horms                                             horms@vergenet.net
 *
 * perdition
 * Mail retrieval proxy server 
 * Copyright (C) 1999-2002  Horms
 * 
 * Code largely borrowed from the Samba Project
 * Copyright (C) 2001 Andrew Tridgell
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

#ifndef _PERDITION_INT_H
#define _PERDITION_INT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Define int8, uint8, int16, uint16, int32 and uint32 */

#ifndef int8
#if (SIZEOF_CHAR != 1)
#error Cannot determine type for int8
#else
#define int8 char
#endif
#endif

#ifndef uint8
#if (SIZEOF_CHAR != 1)
#define Cannot determine type for uint8
#else
#define uint8 unsigned char
#endif
#endif

#ifndef int16 
#if (SIZEOF_SHORT != 2)
#error Cannot determine type for int16
#else 
#define int16 short
#endif 
#endif

#ifndef uint16 
#if (SIZEOF_SHORT != 2)
#error Cannot determine type for uint16
#else 
#define uint16 unsigned short
#endif 
#endif

#ifndef int32 
#if (SIZEOF_INT == 4)
#define int32 int
#elif (SIZEOF_LONG == 4)
#define int32 long
#error Cannot determing tupe for int32
#endif
#endif

#ifndef uint32 
#if (SIZEOF_INT == 4)
#define uint32 unsigned int
#elif (SIZEOF_LONG == 4)
#define uint32 unsigned long
#else
#error Cannot determing tupe for uint32
#endif
#endif

#endif
