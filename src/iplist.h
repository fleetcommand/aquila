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

#ifndef _IPLIST_H_
#define _IPLIST_H_

#include "hash.h"
#include "defaults.h"

typedef struct iplistentry {
  struct iplistentry *next;
  time_t	stamp;
  unsigned long ip;
} iplistentry_t;

typedef struct iplisthashbucket {
  iplistentry_t *first;
  iplistentry_t *last;
} iplisthashbucket_t;

typedef struct iplist {
  unsigned int count;

  unsigned long found;
  unsigned long new;

  iplistentry_t *freelist;
  iplisthashbucket_t ht[IPLIST_HASHSIZE];
  iplistentry_t *mem;
} iplist_t;

extern void iplist_clean (iplist_t *list);
extern int iplist_add (iplist_t *list, unsigned long ip);
extern int iplist_find (iplist_t *list, unsigned long ip);
extern void iplist_init (iplist_t *list);

extern unsigned long iplist_interval;
extern unsigned long iplist_size;

#endif
