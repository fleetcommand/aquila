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
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "defaults.h"

#include "buffer.h"

buffer_stats_t bufferstats;
buffer_t static_buf;

void bf_verify (buffer_t * buffer)
{
  ASSERT (buffer->refcnt > 0);
  ASSERT (buffer->e <= (buffer->buffer + buffer->size));
}

buffer_t *bf_enlarge (buffer_t * buf, unsigned long size)
{
  buffer_t *b = bf_copy (buf, size);

  bf_free (buf);
  return b;
}

buffer_t *bf_alloc (unsigned long size)
{
  buffer_t *b;

  /* alloc buffer */
  b = malloc (size + sizeof (buffer_t));
  ASSERT (b);
  if (!b)
    return NULL;

  /* init buffer */
  memset (b, 0, sizeof (buffer_t) + size);

  b->buffer = ((unsigned char *) b) + sizeof (buffer_t);
  b->s = b->buffer;
  b->e = b->s;
  b->size = size;
  b->refcnt = 1;

#ifdef DEBUG
  b->magic = 0xA55AB33F;
#endif

  bufferstats.size += size;
  if (bufferstats.size > bufferstats.peak)
    bufferstats.peak = bufferstats.size;
  bufferstats.count++;
  if (bufferstats.max < bufferstats.count)
    bufferstats.max = bufferstats.count;

  return b;
}

void bf_free (buffer_t * buffer)
{
  if (!buffer)
    return;

  ASSERT (buffer != &static_buf);
  ASSERT (buffer->refcnt > 0);
  ASSERT (buffer->e <= (buffer->buffer + buffer->size));
#ifdef DEBUG
  ASSERT (buffer->magic == 0xA55AB33F);
#endif
  bf_free (buffer->next);

  /* if there is still a refcnt, do not free the memory */
  if (--buffer->refcnt)
    return;

  /* real free */
  if (buffer->prev)
    buffer->prev->next = NULL;

  bufferstats.size -= buffer->size;
  bufferstats.count--;

  free (buffer);
}

void bf_free_single (buffer_t * buffer)
{
  if (!buffer)
    return;

  ASSERT (buffer != &static_buf);
  ASSERT (buffer->refcnt > 0);
  ASSERT (buffer->e <= (buffer->buffer + buffer->size));

  /* if there is still a refcnt, do not free the memory */
  if (--buffer->refcnt)
    return;

  /* real free */
  if (buffer->next)
    buffer->next->prev = buffer->prev;
  if (buffer->prev)
    buffer->prev->next = buffer->next;

  bufferstats.size -= buffer->size;
  bufferstats.count--;

  free (buffer);
}

void bf_claim (buffer_t * buffer)
{
  if (!buffer)
    return;

  ASSERT (buffer != &static_buf);

  buffer->refcnt++;

  bf_claim (buffer->next);
}

int bf_append_raw (buffer_t ** buffer, unsigned char *data, unsigned long size)
{
  buffer_t *l, *b;

  b = bf_alloc (size);
  if (!b)
    return -1;

  memcpy (b->buffer, data, size);
  b->e += size;

  /* no list yet */
  if (!*buffer) {
    *buffer = b;
    return 0;
  }

  /* append to list */
  l = *buffer;
  while (l->next)
    l = l->next;
  l->next = b;
  b->prev = l;

  return 0;
}

int bf_append (buffer_t ** buffer, buffer_t * b)
{
  buffer_t *l;

  ASSERT (b != &static_buf);

  /* no list yet */
  if (!*buffer) {
    *buffer = b;
    return 0;
  }

  /* append to list */
  l = *buffer;
  while (l->next) {
    ASSERT (b->refcnt == l->refcnt);
    l = l->next;
  }
  l->next = b;
  b->prev = l;

  return 0;
}

buffer_t *bf_sep (buffer_t ** list, unsigned char *sep)
{
  unsigned char c = '\0';
  unsigned char *p, *s;
  buffer_t *b, *r;
  unsigned long size, l;

  if (!*list)
    return NULL;

  /* first, we determine length */
  size = 0;


  /* search se[erator */
  b = *list;
  s = &c;
  for (; b && (!*s); b = b->next) {
    for (p = b->s; (p < b->e) && (!*s); p++)
      for (s = sep; (*s) && (*s != *p); s++);

    size += (p - b->s);
  };

  /* return if no seperator found */
  if ((!b) && (!*s))
    return NULL;

  /* alloc new buffers */
  r = bf_alloc (size);
  if (!r)
    return NULL;

  /* copy all complete buffers into the dest buffer */
  b = *list;
  l = bf_used (b);
  for (; b && (size > l);) {
    memcpy (r->e, b->s, l);
    size -= l;
    r->e += l;

    b = b->next;
    bf_free_single (*list);
    *list = b;
    if (!b)
      break;

    l = bf_used (b);
  };

  /* add part of next buffer */
  memcpy (r->e, b->s, size);

  /* overwrite seperator and expand buffer */
  r->e[size - 1] = '\0';
  r->e += (size - 1);

  /* remove used data from last buffer */
  b->s += size;

  /* check if the current buffer is empty */
  if (b->s == b->e) {
    b = b->next;
    bf_free_single (*list);
    *list = b;
  }

  return r;
}

buffer_t *bf_sep_char (buffer_t ** list, unsigned char sep)
{
  register unsigned char *p;
  register buffer_t *b;
  buffer_t *r;
  unsigned long size, l;

  if ((!list) || (!(*list)))
    return NULL;

  /* first, we determine length */
  size = 0;

  /* search seperator */
  b = *list;
  p = b->s;
  for (; b; b = b->next) {
    for (p = b->s; (p < b->e) && (*p != sep); p++);
    size += (p - b->s);
    if ((p < b->e) && (*p == sep)) {
      /* eat seperator too */
      p++;
      size++;
      break;
    }
  };

  /* return if no seperator found */
  if (!b)
    return NULL;

  /* alloc new buffers */
  r = bf_alloc (size);
  if (!r)
    return NULL;

  /* copy all complete buffers into the dest buffer */
  b = *list;
  l = bf_used (b);
  for (; b && (size > l);) {
    memcpy (r->e, b->s, l);
    size -= l;
    r->e += l;

    b = b->next;
    bf_free_single (*list);
    *list = b;
    if (!b)
      break;

    l = bf_used (b);
  };

  /* add part of next buffer */
  if (size)
    memcpy (r->e, b->s, size);

  /* overwrite seperator and expand buffer */
  r->e[size - 1] = '\0';
  r->e += (size - 1);

  /* remove used data from last buffer */
  b->s += size;

  /* check if the current buffer is empty */
  if (b->s == b->e) {
    b = b->next;
    bf_free_single (*list);
    *list = b;
  }

  return r;
}

int bf_prepend (buffer_t ** list, buffer_t * buf)
{
  buffer_t *b;

  ASSERT (buf != &static_buf);

  for (b = buf; b->next; b = b->next);

  b->next = *list;
  if (*list)
    (*list)->prev = b;

  *list = buf;

  return 0;
}

buffer_t *bf_copy (buffer_t * src, unsigned long extra)
{
  unsigned long total, l;
  buffer_t *b, *dst;

  total = 0;
  for (b = src; b; b = b->next)
    total += bf_used (b);

  dst = bf_alloc (total + extra);
  if (!dst)
    return NULL;

  for (b = src; b; b = b->next) {
    l = bf_used (b);
    memcpy (dst->e, b->s, l);
    dst->e += l;
  }

  return dst;
}

int bf_strcat (buffer_t * dst, unsigned char *data)
{
  /* FIXME could be optimized to run over the data only once */
  return bf_strncat (dst, data, strlen ((char *) data));
}

int bf_strncat (buffer_t * dst, unsigned char *data, unsigned long length)
{
  if (bf_unused (dst) < length)
    length = bf_unused (dst);

  strncpy ((char *) dst->e, (char *) data, length);
  dst->e += length;

  ASSERT (dst->e <= (dst->buffer + dst->size));

  return length;
}

unsigned long bf_size (buffer_t * src)
{
  unsigned long total = 0;
  buffer_t *b;

  for (b = src; b; b = b->next)
    total += bf_used (b);

  return total;
}

int bf_printf (buffer_t * dst, const char *format, ...)
{
  va_list ap;
  int retval, available;

  /* if the buffer is full, just return */
  available = bf_unused (dst);
  if (!available)
    return 0;

  /* print to the buffer */
  va_start (ap, format);
  retval = vsnprintf (dst->e, available, gettext (format), ap);
  va_end (ap);

  /* make sure dst->e is always valid */
  dst->e += (retval > available) ? available : retval;

  return retval;
}


buffer_t *bf_printf_resize (buffer_t * dst, const char *format, ...)
{
  va_list ap;
  int retval, available;
  unsigned char *s = dst->e;

repeat:
  /* if the buffer is full, resize it */
  available = bf_unused (dst);
  if (available < 2)
    goto resize;

  /* print to the buffer */
  va_start (ap, format);
  retval = vsnprintf (dst->e, available, gettext (format), ap);
  va_end (ap);

  /* make sure dst->e is always valid */
  if (retval >= available)
    goto resize;

  dst->e += retval;

  return dst;

resize:
  {
    buffer_t *b;

    if (bf_used (dst)) {
      b = bf_alloc (dst->size);
    } else {
      b = bf_alloc (dst->size * 2);
    }

    dst->e = s;
    bf_append (&dst, b);
    dst = b;
    s = dst->e;
  }
  goto repeat;
}

int bf_vprintf (buffer_t * dst, const char *format, va_list ap)
{
  int retval, available;

  /* if the buffer is full, just return */
  available = bf_unused (dst);
  if (!available)
    return 0;

  /* print to the buffer */
  retval = vsnprintf (dst->e, available, gettext (format), ap);

  /* make sure dst->e is always valid */
  dst->e += (retval > available) ? available : retval;

  return retval;
}

buffer_t *bf_buffer (unsigned char *text)
{
  static_buf.buffer = static_buf.s = text;
  static_buf.e = text + strlen ((char *) text);
  static_buf.size = static_buf.s - static_buf.e;
  static_buf.refcnt = 1;

  return &static_buf;
}

int bf_memcpy (buffer_t * buffer, void *data, size_t length)
{
  size_t l = length < bf_unused (buffer) ? length : bf_unused (buffer);

  memcpy (buffer->e, data, l);
  buffer->e += l;
  return l;
}
