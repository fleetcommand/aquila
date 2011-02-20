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


#ifndef _ETIMER_H_
#define _ETIMER_H_

#include <sys/time.h>
#include "rbt.h"

typedef struct etimer etimer_t;

typedef int (etimer_handler_t) (void *context);

struct etimer {
  rbt_t rbt;

  unsigned int tovalid, resetvalid;
  struct timeval to, reset;
  
  etimer_handler_t	*handler;
  void 			*context;
};

extern int etimer_start ();

extern etimer_t *etimer_alloc (etimer_handler_t *handler, void *ctxt);
extern void etimer_init (etimer_t *timer, etimer_handler_t *handler, void *ctxt);

extern int etimer_set (etimer_t * s, unsigned long timeout);
extern int etimer_cancel (etimer_t *s);
extern void etimer_free (etimer_t * s);

extern int etimer_checktimers ();

#endif /* _ETIMER_H_ */
