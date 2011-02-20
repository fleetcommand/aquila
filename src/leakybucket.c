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

#include "leakybucket.h"

__inline__ int get_token (leaky_bucket_type_t * type, leaky_bucket_t * bucket, time_t now)
{
  if (bucket->tokens) {
    bucket->tokens--;
    return 1;
  }

  if (bucket->lasteval != now) {
    unsigned long t;

    /* bad setting, but it shouldn't cause a crash */
    if (!type->period)
      return 0;

    t = ((now - bucket->timestamp) / type->period);
    bucket->timestamp += type->period * t;
    bucket->lasteval = now;
    bucket->tokens += (t * type->refill);
    /* never store more tokens than the burst value */
    if (bucket->tokens > type->burst)
      bucket->tokens = type->burst;
  }

  if (!bucket->tokens)
    return 0;

  bucket->tokens--;
  return 1;
}

__inline__ void init_bucket (leaky_bucket_t * bucket, unsigned long now)
{
  bucket->lasteval = now;
  bucket->timestamp = now;
  bucket->tokens = 0;
}

__inline__ void init_bucket_type (leaky_bucket_type_t * type, unsigned long period,
				  unsigned long burst, unsigned long refill)
{
  type->period = period;
  type->burst = burst;
  type->refill = refill;
}
