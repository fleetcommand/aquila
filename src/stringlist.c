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

#include <stdio.h>
#include <stdlib.h>
#ifdef DEBUG
#include <string.h>
#endif
#include "defaults.h"

#include "stringlist.h"

inline void string_list_init (string_list_t * list)
{
  list->first = NULL;
  list->last = NULL;
  list->count = 0;
  list->size = 0;
}

inline string_list_entry_t *string_list_add (string_list_t * list, struct user *user,
					     buffer_t * data)
{
  string_list_entry_t *entry;

  entry = malloc (sizeof (string_list_entry_t));
  entry->next = NULL;
  entry->user = user;
  entry->data = data;
  entry->prev = list->last;
  if (list->last)
    list->last->next = entry;
  list->last = entry;
  if (!list->first)
    list->first = entry;

  list->count++;
  list->size += bf_size (data);

  bf_claim (data);
#ifdef DEBUG
  entry->size = bf_size (data);
#endif

  STRINGLIST_VERIFY (list);

  return entry;
}

inline void string_list_del (string_list_t * list, string_list_entry_t * entry)
{

  STRINGLIST_VERIFY (list);

  if (entry->next) {
    entry->next->prev = entry->prev;
  } else {
    list->last = entry->prev;
  }
  if (entry->prev) {
    entry->prev->next = entry->next;
  } else {
    list->first = entry->next;
  }
  if (entry->data) {
    ASSERT (bf_size (entry->data) == entry->size);
    list->size -= bf_size (entry->data);
    bf_free (entry->data);
  }
#ifdef DEBUG
  memset (entry, 0xA5, sizeof (string_list_entry_t));
#endif

  free (entry);
  list->count--;

  STRINGLIST_VERIFY (list);
}

inline void string_list_purge (string_list_t * list, struct user *user)
{
  string_list_entry_t *entry, *next;

  STRINGLIST_VERIFY (list);

  entry = list->first;
  while (entry) {
    next = entry->next;
    if (entry->user == user)
      string_list_del (list, entry);
    entry = next;
  };

  STRINGLIST_VERIFY (list);
}

inline string_list_entry_t *string_list_find (string_list_t * list, struct user *user)
{
  string_list_entry_t *entry, *next;

  STRINGLIST_VERIFY (list);

  entry = list->first;
  while (entry) {
    next = entry->next;
    if (entry->user == user)
      return entry;
    entry = next;
  };


  STRINGLIST_VERIFY (list);

  return NULL;
}

inline void string_list_clear (string_list_t * list)
{
  string_list_entry_t *entry, *next;

  STRINGLIST_VERIFY (list);

  entry = list->first;
  while (entry) {
    next = entry->next;
    if (entry->data)
      bf_free (entry->data);
    free (entry);
    entry = next;
  };
  list->first = NULL;
  list->last = NULL;
  list->count = 0;
  list->size = 0;

  STRINGLIST_VERIFY (list);

}

#ifdef DEBUG
inline void string_list_verify (string_list_t * list)
{
  unsigned long size, count;
  string_list_entry_t *entry, *prev;

  if (!list->first) {
    ASSERT (!list->last);
    ASSERT (!list->count);
    ASSERT (!list->size);
    return;
  }
  ASSERT (list->last);
  ASSERT (list->count);

  size = 0;
  count = 0;
  prev = entry = list->first;
  while (entry) {
    count++;
    size += bf_size (entry->data);
    ASSERT (entry->size == bf_size (entry->data));
    prev = entry;
    entry = entry->next;
  };
  ASSERT (list->last == prev);
  ASSERT (list->size == size);
  ASSERT (list->count == count);
}
#endif
