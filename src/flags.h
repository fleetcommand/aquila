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

#ifndef _FLAGS_H_
#define _FLAGS_H_

#include "buffer.h"

typedef struct flag {
  unsigned char *name;
  unsigned long long flag;
  unsigned char *help;
} flag_t;

extern unsigned int flags_print (flag_t * flags, buffer_t * buf,
					 unsigned long long flag);
extern unsigned int flags_help (flag_t * flags, buffer_t * buf);
extern unsigned int flags_parse (flag_t * flags, buffer_t * buf, unsigned int argc,
					 unsigned char **argv, unsigned int flagstart,
					 unsigned long long *flag, unsigned long long *nflag);

#endif
