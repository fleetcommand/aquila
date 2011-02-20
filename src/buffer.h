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

#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>

#ifdef DEBUG
#define BF_VERIFY(x) if (x) {ASSERT (x->refcnt > 0); ASSERT (x->e <= (x->buffer + x->size)); }
#else
#define BF_VERIFY(x) /* x */
#endif

typedef struct buffer_stats {
  unsigned long long peak;
  unsigned long long size;
  unsigned long count;
  unsigned long max;
} buffer_stats_t;

/* remark:
 *   the buffer is allocated so that:
 *   the b->s pointer can be passed to "free"
 *   it will also make the list very overwrite sesitive
 */

typedef struct buffer {
  struct buffer *next, *prev;

  unsigned char *buffer,	/* pointer to the real buffer */
   *s,				/* start or the data */
   *e;				/* pointer to the first unused byte */
  unsigned long size;		/* allocation size of the buffer */
  unsigned int refcnt;		/* reference counter of the buffer */
#ifdef DEBUG
  unsigned long magic;
#endif
} buffer_t;

extern buffer_stats_t bufferstats;

#define bf_used(buffer) 	((unsigned long)(buffer->e - buffer->s))
#define bf_unused(buf) 	((unsigned long)(buf->buffer + buf->size - buf->e))
#define bf_clear(buf)	(buf->e = buf->s)

extern buffer_t *bf_alloc (unsigned long size);
extern void bf_free (buffer_t * buffer);
extern void bf_free_single (buffer_t * buffer);
extern void bf_claim (buffer_t * buffer);
extern void bf_verify (buffer_t *buffer);

extern int bf_append_raw (buffer_t ** buffer, unsigned char *data, unsigned long size);
extern int bf_append (buffer_t ** buffer, buffer_t * b);

extern buffer_t *bf_sep (buffer_t ** list, unsigned char *sep);
extern buffer_t *bf_sep_char (buffer_t ** list, unsigned char sep);
extern int bf_prepend (buffer_t ** list, buffer_t * buf);

extern buffer_t *bf_copy (buffer_t * src, unsigned long extra);
extern buffer_t *bf_enlarge (buffer_t *buf, unsigned long size);

extern int bf_strcat (buffer_t * dst, unsigned char *data);
extern int bf_strncat (buffer_t * dst, unsigned char *data, unsigned long length);
extern int bf_printf (buffer_t * dst, const char *format, ...);
extern int bf_vprintf (buffer_t * dst, const char *format, va_list ap);
extern buffer_t * bf_printf_resize (buffer_t * dst, const char *format, ...);

extern unsigned long bf_size (buffer_t * src);

extern buffer_t *bf_buffer (unsigned char *text);
extern int bf_memcpy (buffer_t *buffer, void *data, size_t length);

#endif
