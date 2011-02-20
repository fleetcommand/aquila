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

#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "iplist.h"
#include "aqtime.h"
#include "hash.h"

unsigned long iplist_interval = IPLIST_TIME;
unsigned long iplist_size = IPLIST_SIZE;

void iplist_clean (iplist_t * list)
{
  unsigned int i;
  iplisthashbucket_t *hb;
  iplistentry_t *entry, *prev, *next;
  time_t age;

  age = now.tv_sec - iplist_interval;

  for (i = 0; i < IPLIST_HASHSIZE; i++) {
    hb = &(list->ht[i]);

    prev = NULL;
    entry = hb->first;
    while (entry) {
      next = entry->next;
      if (entry->stamp >= age)
	break;

      if (prev) {
	prev->next = next;
      } else {
	hb->first = next;
	if (next == NULL)
	  hb->last = NULL;
      }
      entry->next = list->freelist;
      list->freelist = entry;
      list->count--;
      entry = next;
    }
  }
}

int iplist_add (iplist_t * list, unsigned long ip)
{
  iplisthashbucket_t *hb;
  iplistentry_t *entry;

  entry = list->freelist;
  if (!entry)
    return 0;

  list->freelist = entry->next;
  entry->next = NULL;
  entry->stamp = now.tv_sec;
  entry->ip = ip;
  list->count++;

  hb = &list->ht[one_at_a_time (ip) % IPLIST_HASHMASK];

  if (hb->last) {
    hb->last->next = entry;
  } else {
    hb->first = entry;
  }
  hb->last = entry;

  return 1;
};

int iplist_find (iplist_t * list, unsigned long ip)
{
  iplisthashbucket_t *hb;
  iplistentry_t *entry, *prev, *next;
  time_t age;

  hb = &list->ht[one_at_a_time (ip) % IPLIST_HASHMASK];
  if (!hb)
    goto allow;

  age = now.tv_sec - iplist_interval;

  prev = NULL;
  entry = hb->first;
  while (entry) {
    next = entry->next;
    if (entry->stamp < age) {
      if (prev) {
	prev->next = next;
      } else {
	hb->first = next;
	if (next == NULL)
	  hb->last = NULL;
      }
      entry->next = list->freelist;
      list->freelist = entry;
      list->count--;
      entry = next;
      continue;
    }

    if (entry->ip == ip) {
      if (next != NULL) {
	if (prev != NULL) {
	  prev->next = next;
	} else {
	  hb->first = next;
	}
	entry->next = NULL;
	hb->last->next = entry;
	hb->last = entry;
      }
      entry->stamp = now.tv_sec;
      list->found++;
      return 1;
    }

    prev = entry;
    entry = next;
  }

allow:
  list->new++;

  return 0;
}

void iplist_init (iplist_t * list)
{
  unsigned int i = 0;
  iplistentry_t *entry;

  memset (list, 0, sizeof (iplist_t));
  list->mem = malloc (sizeof (iplistentry_t) * iplist_size);
  memset (list->mem, 0, sizeof (iplistentry_t) * iplist_size);

  for (entry = list->mem, i = 0; i < iplist_size; i++, entry++)
    entry->next = (entry + 1);
  (--entry)->next = NULL;
  list->freelist = list->mem;
};
