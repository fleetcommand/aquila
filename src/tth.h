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
#ifndef _TTH_H_
#define _TTH_H_
#include "buffer.h"
#include <time.h>

#define TTH_BYTELENGTH	24

typedef struct tth {
  unsigned char bytes[TTH_BYTELENGTH];
} tth_t;

typedef struct tth_list_entry {
  time_t stamp;
  tth_t tth;
} tth_list_entry_t;

typedef struct tth_list {
  unsigned int start, end, num, count;
  tth_list_entry_t *entries;
} tth_list_t;

extern unsigned int tth_harvest (tth_t *tth, unsigned char *s);
extern tth_list_entry_t * tth_list_check (tth_list_t *list, tth_t *tth, unsigned long interval);
extern unsigned int tth_list_add (tth_list_t *list, tth_t *tth, time_t time);
extern tth_list_t * tth_list_alloc (unsigned int size);

#endif
