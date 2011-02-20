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

#include "dllist.h"
#include <errno.h>
#include <string.h>

__inline__ void dllist_del (dllist_entry_t * e)
{
  e->next->prev = e->prev;
  e->prev->next = e->next;
}

__inline__ void dllist_append (dllist_entry_t * list, dllist_entry_t * new)
{
  new->next = list->next;
  new->next->prev = new;
  new->prev = list;
  list->next = new;
}

__inline__ void dllist_prepend (dllist_entry_t * list, dllist_entry_t * new)
{
  new->prev = list->prev;
  new->prev->next = new;
  new->next = list;
  list->prev = new;
}

__inline__ void dllist_init (dllist_entry_t * list)
{
  list->next = list;
  list->prev = list;
}

__inline__ int dlhashlist_init (dllist_t * list, unsigned long buckets)
{
  unsigned long i;
  dllist_entry_t *e;

  if (!list->hashlist) {
    list->hashlist = malloc (sizeof (dllist_entry_t) * buckets);
    memset (list->hashlist, 0, sizeof (dllist_entry_t) * buckets);
  }

  if (!list->hashlist)
    return -errno;

  list->buckets = buckets;
  for (i = 0, e = list->hashlist; i < buckets; i++, e++) {
    e->next = e;
    e->prev = e;
  }
  return 0;
}
