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

#include "etimer.h"
#include "defaults.h"

rbt_t *root = NULL;
unsigned long timercnt = 0;

/************************************************************************
**
**                             TIMERS
**
************************************************************************/
int etimer_set (etimer_t * timer, unsigned long timeout)
{
  unsigned long long key;

  if (!timeout) {
    if (timer->tovalid)
      etimer_cancel (timer);
    return 0;
  }

  ASSERT (timer->handler);

  /* if timer is valid already and the new time is later than the old, just set the reset time... 
   * it will be handled when the timer expires 
   */
  if (timer->tovalid) {
    gettimeofday (&timer->reset, NULL);
    timer->reset.tv_sec += timeout / 1000;
    timer->reset.tv_usec += ((timeout * 1000) % 1000000);
    if (timer->reset.tv_usec > 1000000) {
      timer->reset.tv_sec++;
      timer->reset.tv_usec -= 1000000;
    }

    /* new time is later than the old */
    if (timercmp (&timer->reset, &timer->to, >)) {
      timer->resetvalid = 1;

      return 0;
    } else {
      etimer_cancel (timer);
    }
    timer->to = timer->reset;
  } else
    gettimeofday (&timer->to, NULL);

  /* determine key */
  key = (timer->to.tv_sec * 1000LL) + (timer->to.tv_usec / 1000LL) + timeout;

  /* create timeout */
  timer->to.tv_sec += timeout / 1000;
  timer->to.tv_usec += ((timeout * 1000) % 1000000);
  if (timer->to.tv_usec > 1000000) {
    timer->to.tv_sec++;
    timer->to.tv_usec -= 1000000;
  }
  timer->tovalid = 1;

  /* insert into rbt */
  timer->rbt.data = key;
  insertNode (&root, &timer->rbt);
  timercnt++;

  return 0;
}

int etimer_cancel (etimer_t * timer)
{

  if (!timer->tovalid)
    return 0;

  deleteNode (&root, &timer->rbt);

  timer->resetvalid = 0;
  timer->tovalid = 0;

  return 0;
}

void etimer_init (etimer_t * timer, etimer_handler_t * handler, void *ctxt)
{
  ASSERT (handler);
  memset (timer, 0, sizeof (etimer_t));
  timer->handler = handler;
  timer->context = ctxt;
}

etimer_t *etimer_alloc (etimer_handler_t * handler, void *ctxt)
{
  etimer_t *timer;

  timer = malloc (sizeof (etimer_t));
  if (!timer)
    return NULL;

  memset (timer, 0, sizeof (etimer_t));
  timer->handler = handler;
  timer->context = ctxt;

  return timer;
};

void etimer_free (etimer_t * timer)
{
  if (timer->tovalid)
    deleteNode (&root, &timer->rbt);

  free (timer);
};



int etimer_checktimers ()
{
  etimer_t *timer;
  rbt_t *rbt;
  struct timeval now;

  gettimeofday (&now, NULL);

  /* handle timers */
  while ((rbt = smallestNode (&root))) {
    timer = (etimer_t *) rbt;

    ASSERT (timer->tovalid);

    if (!timercmp ((&timer->to), (&now), <))
      return 0;

    if (timer->resetvalid) {
      unsigned long long key = (timer->reset.tv_sec * 1000LL) + (timer->reset.tv_usec / 1000LL);

      timer->to = timer->reset;
      timer->resetvalid = 0;

      deleteNode (&root, rbt);

      timer->rbt.data = key;
      insertNode (&root, rbt);
      continue;
    }

    timer->tovalid = 0;
    deleteNode (&root, rbt);
    timercnt--;

    timer->handler (timer->context);
  }
  return 0;
}

int etimer_start ()
{
  initRoot (&root);
  return 0;
}
