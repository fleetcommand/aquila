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

#include "hub.h"

#include "utils.h"

#include "aqtime.h"
#include "nmdc_protocol.h"
#include "nmdc_local.h"
#include "nmdc_utils.h"

/******************************************************************************\
**                                                                            **
**                            NICKLIST CACHING                                **
**                                                                            **
\******************************************************************************/

#ifdef DEBUG
void nicklistcache_verify ()
{
  user_t *u;
  unsigned long le = 0, lei = 0, leo = 0;

  for (u = userlist; u; u = u->next) {
    if ((u->state != PROTO_STATE_ONLINE) && (u->state != PROTO_STATE_VIRTUAL))
      continue;
    if (u->rights & CAP_HIDDEN)
      continue;
    le += strlen (u->nick) + 2;
    lei += bf_used (u->MyINFO) + 1;
    if (u->op)
      leo += strlen (u->nick) + 2;
  }

  for (u = cachelist; u; u = u->next) {
    if (!u->joinstamp)
      continue;
    if (u->rights & CAP_HIDDEN)
      continue;
    le += strlen (u->nick) + 2;
    lei += bf_used (u->MyINFO) + 1;
    if (u->op)
      leo += strlen (u->nick) + 2;
  }
  ASSERT (le == cache.length_estimate);
  ASSERT (lei == cache.length_estimate_info);
  ASSERT (leo == cache.length_estimate_op);
}
#endif

int nicklistcache_adduser (user_t * u)
{
  unsigned long l;

  if (u->rights & CAP_HIDDEN)
    return 0;

  l = strlen (u->nick) + 2;
  cache.length_estimate += l;
  cache.length_estimate_info += bf_used (u->MyINFO) + 1;	/* add one for the | */

  u->flags |= NMDC_FLAG_CACHED;

  cache.usercount++;

  if (!(u->supports & NMDC_SUPPORTS_NoGetINFO))
    u->rate_getinfo.tokens += cache.usercount;

  if (u->op) {
    cache.length_estimate_op += l;
    cache.needrebuild = 1;
  }

  NICKLISTCACHE_VERIFY;

  if (cache.needrebuild)
    return 0;

  /* append the myinfo message */
  l = bf_used (u->MyINFO);
  if (l >= bf_unused (cache.infolistupdate)) {
    cache.needrebuild = 1;
    return 0;
  }

  bf_strncat (cache.infolistupdate, u->MyINFO->s, l);
  bf_strcat (cache.infolistupdate, "|");
  bf_printf (cache.hellolist, "$Hello %s|", u->nick);

  BF_VERIFY (cache.infolistupdate);
  BF_VERIFY (cache.hellolist);

  return 0;
}

int nicklistcache_updateuser (user_t * old, user_t * new)
{
  if (new->rights & CAP_HIDDEN)
    return 0;

  if (old->op != new->op) {
    unsigned long l = strlen (new->nick) + 2;

    if (old->op && (cache.length_estimate_op > l))
      cache.length_estimate_op -= l;
    if (new->op)
      cache.length_estimate_op += l;
  }
  return nicklistcache_updatemyinfo (old->MyINFO, new->MyINFO);
}

int nicklistcache_updatemyinfo (buffer_t * old, buffer_t * new)
{
  unsigned long l;

  l = bf_used (old);
  if (l < cache.length_estimate_info)
    cache.length_estimate_info -= bf_used (old);
  cache.length_estimate_info += bf_used (new);

  NICKLISTCACHE_VERIFY;

  if (cache.needrebuild)
    return 0;

  l = bf_used (new);
  if (l > bf_unused (cache.infolistupdate)) {
    cache.needrebuild = 1;
    return 0;
  }

  bf_strncat (cache.infolistupdate, new->s, l);
  bf_strcat (cache.infolistupdate, "|");

  BF_VERIFY (cache.infolistupdate);

  return 0;
}

int nicklistcache_deluser (user_t * u)
{
  unsigned long l;

  if (!(u->flags & NMDC_FLAG_CACHED))
    return 0;

  if (u->rights & CAP_HIDDEN)
    return 0;

  l = (bf_used (u->MyINFO) + 1);
  if (l < cache.length_estimate_info)
    cache.length_estimate_info -= l;
  l = (strlen (u->nick) + 2);
  if (l < cache.length_estimate)
    cache.length_estimate -= l;

  cache.usercount--;

  if (u->op) {
    cache.needrebuild = 1;
    cache.length_estimate_op -= l;
  }

  u->flags &= ~NMDC_FLAG_CACHED;

  NICKLISTCACHE_VERIFY;

  if (cache.needrebuild)
    return 0;

  if (bf_unused (cache.infolistupdate) < (strlen (u->nick) + 8)) {
    cache.needrebuild = 1;
    return 0;
  }

  bf_printf (cache.infolistupdate, "$Quit %s|", u->nick);
  bf_printf (cache.hellolist, "$Quit %s|", u->nick);

  BF_VERIFY (cache.infolistupdate);
  BF_VERIFY (cache.hellolist);

  return 0;
}

int nicklistcache_rebuild (struct timeval now)
{
  unsigned char *s, *o;
  user_t *t;

  NICKLISTCACHE_VERIFY;

  nmdc_stats.cacherebuild++;

  DPRINTF (" Rebuilding cache\n");
#ifdef ZLINES
  if (cache.infolistzpipe != cache.infolist)
    bf_free (cache.infolistzpipe);
  cache.infolistzpipe = NULL;
  if (cache.infolistzline != cache.infolist)
    bf_free (cache.infolistzline);
  cache.infolistzline = NULL;

  if (cache.nicklistzpipe != cache.nicklist)
    bf_free (cache.nicklistzpipe);
  cache.nicklistzpipe = NULL;
  if (cache.nicklistzline != cache.nicklist)
    bf_free (cache.nicklistzline);
  cache.nicklistzline = NULL;
#endif
  bf_free (cache.nicklist);
  bf_free (cache.oplist);
  bf_free (cache.infolist);
  bf_free (cache.infolistupdate);
  bf_free (cache.hellolist);

  cache.nicklist = bf_alloc (cache.length_estimate + 32);
  s = cache.nicklist->buffer;
  cache.oplist = bf_alloc (cache.length_estimate_op + 32);
  o = cache.oplist->buffer;
  cache.infolist = bf_alloc (cache.length_estimate_info + 32);
  cache.infolistupdate = bf_alloc ((cache.length_estimate_info >> NICKLISTCACHE_SPARE) + 32);
  cache.hellolist = bf_alloc (cache.length_estimate_info + 32);

  s += sprintf (s, "$NickList ");
  o += sprintf (o, "$OpList ");
  for (t = userlist; t; t = t->next) {
    if ((t->state != PROTO_STATE_ONLINE) && (t->state != PROTO_STATE_VIRTUAL))
      continue;
    if (t->rights & CAP_HIDDEN)
      continue;
    bf_strncat (cache.infolist, t->MyINFO->s, bf_used (t->MyINFO));
    bf_strcat (cache.infolist, "|");
    s += sprintf (s, "%s$$", t->nick);
    if (t->op)
      o += sprintf (o, "%s$$", t->nick);
  }
  strcat (s++, "|");
  cache.nicklist->e = s;
  strcat (o++, "|");
  cache.oplist->e = o;

  cache.needrebuild = 0;
  cache.lastrebuild = now.tv_sec;


#ifdef ZLINES
  zline (cache.infolist, cache.ZpipeSupporters ? &cache.infolistzpipe : NULL,
	 cache.ZlineSupporters ? &cache.infolistzline : NULL);
  zline (cache.nicklist, cache.ZpipeSupporters ? &cache.nicklistzpipe : NULL,
	 cache.ZlineSupporters ? &cache.nicklistzline : NULL);
#endif

  cache.nicklist_length = bf_used (cache.nicklist);
  cache.oplist_length = bf_used (cache.oplist);
  cache.infolist_length = bf_used (cache.infolist);
  cache.hellolist_length = bf_used (cache.hellolist);
#ifdef ZLINES
  cache.infolistzline_length = cache.infolistzline ? bf_used (cache.infolistzline) : 0;
  cache.nicklistzline_length = cache.nicklistzline ? bf_used (cache.nicklistzline) : 0;
  cache.infolistzpipe_length = cache.infolistzpipe ? bf_used (cache.infolistzpipe) : 0;
  cache.nicklistzpipe_length = cache.nicklistzpipe ? bf_used (cache.nicklistzpipe) : 0;
#endif
  cache.infolistupdate_length = bf_used (cache.infolistupdate);


  BF_VERIFY (cache.infolist);
  BF_VERIFY (cache.nicklist);
  BF_VERIFY (cache.oplist);
#ifdef ZLINES
  BF_VERIFY (cache.infolistzline);
  BF_VERIFY (cache.infolistzpipe);
  BF_VERIFY (cache.nicklistzline);
  BF_VERIFY (cache.nicklistzpipe);
#endif

  return 0;
}

int nicklistcache_sendnicklist (user_t * target)
{
  buffer_t *b = NULL;

  if ((now.tv_sec - cache.lastrebuild) > PROTOCOL_REBUILD_PERIOD)
    cache.needrebuild = 1;

  if (cache.needrebuild)
    nicklistcache_rebuild (now);

  /* do not send out a nicklist to nohello clients: they have enough with the infolist 
   * unless they do not support NoGetINFO. Very nice. NOT.
   */
  if (!(target->supports & NMDC_SUPPORTS_NoHello)) {
#ifdef ZLINES
    if (target->supports & NMDC_SUPPORTS_ZPipe) {
      server_write_credit (target->parent, cache.nicklistzpipe);
      cache.nicklistzpipe_count++;
    } else if (target->supports & NMDC_SUPPORTS_ZLine) {
      server_write_credit (target->parent, cache.nicklistzline);
      cache.nicklistzline_count++;
    } else {
      server_write_credit (target->parent, cache.nicklist);
      cache.nicklist_count++;
    }
#else
    server_write_credit (target->parent, cache.nicklist);
    cache.nicklist_count++;
#endif
  } else {
    if (!(target->supports & NMDC_SUPPORTS_NoGetINFO)) {
      server_write_credit (target->parent, cache.nicklist);
      cache.nicklist_count++;
    }
  }
  /* always send the oplist */
  server_write_credit (target->parent, cache.oplist);
  cache.oplist_count++;

  /* clients that support NoGetINFO get a infolist and a infolistupdate, other get a  hello list update */
  if (target->supports & NMDC_SUPPORTS_NoGetINFO) {
#ifdef ZLINES
    if (target->supports & NMDC_SUPPORTS_ZPipe) {
      server_write_credit (target->parent, cache.infolistzpipe);
      cache.infolistzpipe_count++;
    } else if (target->supports & NMDC_SUPPORTS_ZLine) {
      server_write_credit (target->parent, cache.infolistzline);
      cache.infolistzline_count++;
    } else {
      server_write_credit (target->parent, cache.infolist);
      cache.infolist_count++;
    }
#else
    server_write_credit (target->parent, cache.infolist);
    cache.infolist_count++;
#endif
#ifdef ZLINES
    if (target->supports & NMDC_SUPPORTS_ZPipe) {
      zline (cache.infolistupdate, &b, NULL);
    } else if (target->supports & NMDC_SUPPORTS_ZLine) {
      zline (cache.infolistupdate, NULL, &b);
    }
#endif
    if ((!b) || (b == cache.infolistupdate))
      b = bf_copy (cache.infolistupdate, 0);

    server_write_credit (target->parent, b);
    bf_free (b);
    cache.infolistupdate_bytes += bf_used (b);
  } else {
    server_write_credit (target->parent, cache.hellolist);
    cache.hellolist_count++;
  }

  return 0;
}

int nicklistcache_sendoplist (user_t * target)
{
  nicklistcache_rebuild (now);

  /* 
     write out to all users except target. 
     FIXME this wouldn't help since we don't tag the oplist as send by the user...
     target->SearchCnt++;
     target->CacheException++;
   */

  /* we set the user to NULL so we don't get deleted by a search from this user */
  cache_queue (cache.asearch, NULL, cache.oplist);
  cache_queue (cache.psearch, NULL, cache.oplist);

  return 0;
}
