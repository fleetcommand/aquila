/*                                                                                                                                    
 *  (C) Copyright 2006 Johan Verrept (jove@users.berlios.de)                                                                      
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *  
 */

#ifndef _NMDC_UTILS_H_
#define _NMDC_UTILS_H_
#include "hub.h"

/* minimum number of bytes in the buffer before you decide to actually compress it. */
#define ZLINES_THRESHOLD	100

extern int nmdc_string_unescape (char *output, unsigned int j);
extern int parse_tag (char *desc, user_t * user);
extern buffer_t *rebuild_myinfo (user_t * u, buffer_t * b);

#ifdef ZLINES

extern int zline (buffer_t *, buffer_t **, buffer_t **);
extern buffer_t *zunline (buffer_t * input);

#endif

#endif /* _NMDC_UTILS_H_ */
