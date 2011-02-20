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

#ifndef _LEAKY_BUCKET_H_
#define _LEAKY_BUCKET_H_

#include <sys/types.h>

typedef struct leaky_bucket {
  time_t timestamp;
  time_t lasteval;
  unsigned long tokens;
} leaky_bucket_t;

typedef struct leaky_bucket_type {
  unsigned long period;
  unsigned long burst;
  unsigned long refill;
} leaky_bucket_type_t;

extern inline int get_token (leaky_bucket_type_t * type, leaky_bucket_t * bucket, time_t now);
extern inline void init_bucket (leaky_bucket_t * bucket, unsigned long now);
extern inline void init_bucket_type (leaky_bucket_type_t * type, unsigned long period,
				     unsigned long burst, unsigned long refill);

#endif
