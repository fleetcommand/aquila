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

#include <string.h>

#include "tth.h"

#define LISTINC(x, max)	x = (x+1)%max
#define VERIFYBYTE(byte) if ((byte < '2')||(byte > 'Z')||((byte > '7')&&(byte < 'A'))) return 0;
#define CONVERTBYTE(byte) byte = (((byte < 'A') ? 26 + (byte - '2') : byte - 'A')<<3)


unsigned int tth_harvest (tth_t * tth, unsigned char *s)
{
  unsigned int i, offset, o, n;
  unsigned char *match, byte;

  match = strstr (s, "TTH:");
  if (!match)
    return 0;

  memset (tth->bytes, 0, TTH_BYTELENGTH);
  match += 4;

  /* convert byte32 encoding */
  for (i = 0, offset = 0; i < 38; i++, offset += 5) {
    byte = match[i];
    VERIFYBYTE (byte);
    CONVERTBYTE (byte);
    n = offset / 8;
    o = offset % 8;
    tth->bytes[n] |= byte >> o;
    if (o > 3)
      tth->bytes[n + 1] |= byte << (8 - o);
  }

  /* convert last byte32 byte */
  byte = match[i];
  VERIFYBYTE (byte);
  CONVERTBYTE (byte);
  n = offset / 8;
  o = offset % 8;
  tth->bytes[n] |= byte >> o;

  return 1;
}

tth_list_entry_t *tth_list_check (tth_list_t * list, tth_t * tth, unsigned long interval)
{
  unsigned int i, j, n;
  time_t limit;
  tth_list_entry_t *e;

  if (!list->count)
    return 0;

  time (&limit);
  limit -= interval;

  j = (list->start < list->end) ? list->end : list->end + list->num;
  for (i = list->start; i < j; i++) {
    n = i % list->num;
    e = &list->entries[n];
    if (e->stamp < limit) {
      list->start = n;
      continue;
    }
    if (!memcmp (e->tth.bytes, tth->bytes, TTH_BYTELENGTH))
      return e;
  }
  return NULL;
}

unsigned int tth_list_add (tth_list_t * list, tth_t * tth, time_t time)
{
  if (list->count && (list->end == list->start))
    LISTINC (list->start, list->num);

  list->entries[list->end].stamp = time;
  memcpy (&list->entries[list->end].tth.bytes, tth->bytes, TTH_BYTELENGTH);
  LISTINC (list->end, list->num);
  if (list->count < list->num)
    list->count++;

  return 0;
}

tth_list_t *tth_list_alloc (unsigned int size)
{
  tth_list_t *list;

  if (!size)
    return NULL;

  list = malloc (sizeof (tth_list_t) + (size * sizeof (tth_list_entry_t)));
  if (!list)
    return NULL;

  memset (list, 0, sizeof (tth_list_t) + (size * sizeof (tth_list_entry_t)));
  list->entries = (void *) list + sizeof (tth_list_t);
  list->num = size;

  return list;
}

#ifdef STANDALONE

int main ()
{
  tth_t tth;

  tth_harvest (&tth, "TTH:KGHR4AODXNNQJMFSODEULOLIAY6JLYI5PQUCFAY");
  tth_harvest (&tth, "TTH:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  tth_harvest (&tth, "TTH:777777777777777777777777777777777777777");
}

#endif
