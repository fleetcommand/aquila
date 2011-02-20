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

#ifndef _STRINGLIST_H_
#define _STRINGLIST_H_

#include "buffer.h"

#ifdef DEBUG
#define STRINGLIST_VERIFY(x) string_list_verify(x)
#else
#define STRINGLIST_VERIFY(x)
#endif

struct user;

typedef struct string_list_entry {
  struct string_list_entry *next, *prev;
  struct string_list_entry *hnext, *hprev;
  struct user *user;
  buffer_t *data;
#ifdef DEBUG
  unsigned long size;
#endif
} string_list_entry_t;

typedef struct string_list {
  struct string_list_entry *first, *last, **hash;
  unsigned int count;
  unsigned long size;
} string_list_t;

inline void string_list_init (string_list_t * list);
inline string_list_entry_t *string_list_add (string_list_t * list, struct user *user, buffer_t *);
inline void string_list_del (string_list_t * list, string_list_entry_t * entry);
inline void string_list_purge (string_list_t * list, struct user *user);
inline string_list_entry_t *string_list_find (string_list_t * list, struct user *user);
inline void string_list_clear (string_list_t * list);
inline void string_list_verify (string_list_t * list);

#endif
