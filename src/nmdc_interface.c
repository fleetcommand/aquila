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

#include <sys/types.h>

#ifndef __USE_W32_SOCKETS
#  include <sys/socket.h>
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#  ifdef HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#  endif
#endif /* __USE_W32_SOCKETS */

#include "hub.h"

#include "user.h"
#include "core_config.h"
#include "plugin_int.h"

#include "hashlist_func.h"

#include "aqtime.h"
#include "nmdc_token.h"
#include "nmdc_nicklistcache.h"
#include "nmdc_local.h"

#include "defaults.h"

#include "stats.h"

/******************************************************************************\
**                                                                            **
**                            GLOBAL VARIABLES                                **
**                                                                            **
\******************************************************************************/

plugin_t *plugin_nmdc;

cache_t cache;
ratelimiting_t rates;

user_t *userlist = NULL;

/* special users */
user_t *HubSec;

/* globals */
unsigned int keylen = 0;
unsigned int keyoffset = 0;
char key[16 + sizeof (LOCK) + 4 + LOCKLENGTH + 1];

/* local hub cache */

leaky_bucket_t connects;
nmdc_stats_t nmdc_stats;

banlist_t reconnectbanlist;

unsigned int cloning;

unsigned int chatmaxlength;
unsigned int searchmaxlength;
unsigned int srmaxlength;
unsigned int researchmininterval, researchperiod, researchmaxcount;

unsigned char *defaultbanmessage = NULL;

unsigned char *nickchars;
unsigned char nickchar_map[256];
unsigned char nmdc_forbiddenchars[256];

unsigned int notimeout = 0;

config_element_t *cfg_nickchars;

leaky_bucket_t rate_warnings;

static user_t *freelist = NULL;
hashlist_t hashlist;

unsigned long cachelist_count = 0;
user_t *cachelist = NULL;
user_t *cachelist_last = NULL;
hashlist_t cachehashlist;

/******************************************************************************\
**                                                                            **
**                            FUNCTION PROTOTYPES                             **
**                                                                            **
\******************************************************************************/


/* function prototypes */
int proto_nmdc_setup ();
int proto_nmdc_init ();
int proto_nmdc_handle_token (user_t * u, buffer_t * b);
int proto_nmdc_handle_input (user_t * user, buffer_t ** buffers);
void proto_nmdc_flush_cache ();
int proto_nmdc_user_disconnect (user_t * u, char *reason);
int proto_nmdc_user_forcemove (user_t * u, unsigned char *destination, buffer_t * message);
int proto_nmdc_user_redirect (user_t * u, buffer_t * message);
int proto_nmdc_user_drop (user_t * u, buffer_t * message);
user_t *proto_nmdc_user_find (unsigned char *nick);
user_t *proto_nmdc_user_alloc (void *priv);
int proto_nmdc_user_free (user_t * user);

user_t *proto_nmdc_user_addrobot (unsigned char *nick, unsigned char *description);
int proto_nmdc_user_delrobot (user_t * u);

int proto_nmdc_user_chat_all (user_t * u, buffer_t * message);
int proto_nmdc_user_send (user_t * u, user_t * target, buffer_t * message);
int proto_nmdc_user_send_direct (user_t * u, user_t * target, buffer_t * message);
int proto_nmdc_user_priv (user_t * u, user_t * target, user_t * source, buffer_t * message);
int proto_nmdc_user_priv_direct (user_t * u, user_t * target, user_t * source, buffer_t * message);
int proto_nmdc_user_raw (user_t * target, buffer_t * message);
int proto_nmdc_user_raw_all (buffer_t * message);

int proto_nmdc_warn (struct timeval *now, unsigned char *message, ...);

unsigned long proto_nmdc_handle_timeout (user_t * user);

/******************************************************************************\
**                                                                            **
**                            PROTOCOL DEFINITION                             **
**                                                                            **
\******************************************************************************/

/* callback structure init */
/* *INDENT-OFF* */
proto_t nmdc_proto = {
	init: 			proto_nmdc_init,
	setup:			proto_nmdc_setup,
	
	handle_token:   	proto_nmdc_handle_token,
	handle_input:		proto_nmdc_handle_input,
	flush_cache:    	proto_nmdc_flush_cache,
	
        user_alloc:		proto_nmdc_user_alloc,
        user_free:		proto_nmdc_user_free,

	user_disconnect:	proto_nmdc_user_disconnect,
	user_forcemove:		proto_nmdc_user_forcemove,
	user_redirect:		proto_nmdc_user_redirect,
	user_drop:		proto_nmdc_user_drop,
	user_find:		proto_nmdc_user_find,
	
	robot_add:		proto_nmdc_user_addrobot,
	robot_del:		proto_nmdc_user_delrobot,
	
	chat_main:		proto_nmdc_user_chat_all,
	chat_send:		proto_nmdc_user_send,
	chat_send_direct:	proto_nmdc_user_send_direct,
	chat_priv:		proto_nmdc_user_priv,
	chat_priv_direct:	proto_nmdc_user_priv_direct,
	raw_send:		proto_nmdc_user_raw,
	raw_send_all:		proto_nmdc_user_raw_all,
	
	name:			"NMDC"
};
/* *INDENT-ON* */

/******************************************************************************\
**                                                                            **
**                            ROBOT HANDLING                                  **
**                                                                            **
\******************************************************************************/

int proto_nmdc_user_delrobot (user_t * u)
{
  buffer_t *buf;

  if (u->state != PROTO_STATE_VIRTUAL)
    return -1;

  /* clear the user from all the relevant caches: not chat and not quit */
  string_list_purge (&cache.myinfo.messages, u);
  string_list_purge (&cache.myinfoupdate.messages, u);
  string_list_purge (&cache.myinfoupdateop.messages, u);
  string_list_purge (&cache.asearch.messages, u);
  string_list_purge (&cache.psearch.messages, u);

  buf = bf_alloc (8 + NICKLENGTH);

  bf_strcat (buf, "$Quit ");
  bf_strcat (buf, u->nick);
  bf_strcat (buf, "|");

  cache_queue (cache.myinfo, NULL, buf);
  cache_queue (cache.myinfoupdateop, NULL, buf);

  bf_free (buf);

  plugin_send_event (u->plugin_priv, PLUGIN_EVENT_LOGOUT, NULL);

  /* for nicklistcache_deluser and nicklistcache_verify */
  u->state = PROTO_STATE_DISCONNECTED;

  nicklistcache_deluser (u);
  hash_deluser (&hashlist, &u->hash);

  if (u->MyINFO) {
    bf_free (u->MyINFO);
    u->MyINFO = NULL;
  }

  if (u->plugin_priv)
    plugin_del_user ((void *) &u->plugin_priv);

  /* remove from the current user list */
  if (u->next)
    u->next->prev = u->prev;

  if (u->prev) {
    u->prev->next = u->next;
  } else {
    userlist = u->next;
  };

  free (u);

  return 0;
}

user_t *proto_nmdc_user_addrobot (unsigned char *nick, unsigned char *description)
{
  user_t *u;
  buffer_t *tmpbuf;

  /* create new context */
  u = malloc (sizeof (user_t));
  if (!u)
    return NULL;
  memset (u, 0, sizeof (user_t));

  u->state = PROTO_STATE_VIRTUAL;

  /* add user to the list... */
  u->next = userlist;
  if (u->next)
    u->next->prev = u;
  u->prev = NULL;

  userlist = u;

  /* build MyINFO */
  tmpbuf = bf_alloc (32 + strlen (nick) + strlen (description));
  bf_strcat (tmpbuf, "$MyINFO $ALL ");
  bf_strcat (tmpbuf, nick);
  bf_strcat (tmpbuf, " ");
  bf_strcat (tmpbuf, description);
  bf_printf (tmpbuf, "$ $%c$$0$", 1);

  strncpy (u->nick, nick, NICKLENGTH);
  u->nick[NICKLENGTH - 1] = 0;
  u->MyINFO = bf_copy (tmpbuf, 0);

  bf_free (tmpbuf);

  u->rights = CAP_OP;
  u->op = 1;

  hash_adduser (&hashlist, u);
  nicklistcache_adduser (u);

  /* send it to the users */
  cache_queue (cache.myinfo, u, u->MyINFO);
  cache_queue (cache.myinfoupdateop, u, u->MyINFO);

  return u;
}

/******************************************************************************\
**                                                                            **
**                          FREELIST HANDLING                                **
**                                                                            **
\******************************************************************************/

void proto_nmdc_user_freelist_add (user_t * user)
{
  ASSERT (!user->timer.tovalid);

  user->next = freelist;
  user->prev = NULL;
  freelist = user;
}

void proto_nmdc_user_freelist_clear ()
{
  user_t *o;

  /* destroy freelist */
  while (freelist) {
    o = freelist;
    freelist = freelist->next;

    NICKLISTCACHE_VERIFY;

    ASSERT (!o->timer.tovalid);

    if (o->tthlist)
      free (o->tthlist);

    if (o->MyINFO) {
      bf_free (o->MyINFO);
      o->MyINFO = NULL;
    }

    if (o->plugin_priv)
      plugin_del_user ((void *) &o->plugin_priv);

    free (o);
  }
}

/******************************************************************************\
**                                                                            **
**                          CACHELIST HANDLING                                **
**                                                                            **
\******************************************************************************/

void proto_nmdc_user_cachelist_add (user_t * user)
{

  ASSERT (!user->timer.tovalid);

  user->next = cachelist;
  if (user->next) {
    user->next->prev = user;
  } else {
    cachelist_last = user;
  }
  user->prev = NULL;
  cachelist = user;
  cachelist_count++;
  user->joinstamp = now.tv_sec;
}

void proto_nmdc_user_cachelist_invalidate (user_t * u)
{
  u->joinstamp = 0;
  hash_deluser (&cachehashlist, &u->hash);
}

void proto_nmdc_user_cachelist_clear ()
{
  buffer_t *buf;
  user_t *u, *p;
  time_t tnow;
  unsigned int op;

  tnow = now.tv_sec;
  tnow -= config.DelayedLogout;
  for (u = cachelist_last; u; u = p) {
    p = u->prev;
    if (u->joinstamp >= (unsigned) tnow)
      continue;

    /* a joinstamp of 0 means the user rejoined */
    if (u->joinstamp) {
      /* queue the quit message */
      buf = bf_alloc (8 + NICKLENGTH);
      bf_strcat (buf, "$Quit ");
      bf_strcat (buf, u->nick);
      cache_queue (cache.myinfo, NULL, buf);
      cache_queue (cache.myinfoupdateop, NULL, buf);
      bf_free (buf);

      u->joinstamp = 0;

      nicklistcache_deluser (u);

      /* remove from hashlist */
      hash_deluser (&cachehashlist, &u->hash);

      if (u->op)
	op++;
    }

    /* remove from list */
    if (u->next) {
      u->next->prev = u->prev;
    } else {
      cachelist_last = u->prev;
    }
    if (u->prev) {
      u->prev->next = u->next;
    } else {
      cachelist = u->next;
    };
    cachelist_count--;

    /* put user in freelist */
    proto_nmdc_user_freelist_add (u);

    NICKLISTCACHE_VERIFY;

    u = NULL;
  }
}

/******************************************************************************\
**                                                                            **
**                             CHAT HANDLING                                  **
**                                                                            **
\******************************************************************************/

unsigned int proto_nmdc_user_flush (user_t * u)
{
  buffer_t *b = NULL, *buffer;
  string_list_entry_t *le;

  if (u->state == PROTO_STATE_DISCONNECTED)
    return 0;
  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  buffer = bf_alloc (10240);

  for (le = ((nmdc_user_t *) u->pdata)->privatemessages.messages.first; le; le = le->next) {
    /* data and length */
    b = le->data;
    bf_strncat (buffer, b->s, bf_used (b));
    bf_strcat (buffer, "|");

    u->MessageCnt--;
    u->CacheException--;
  }
  cache_clear ((((nmdc_user_t *) u->pdata)->privatemessages));

  server_write (u->parent, buffer);

  bf_free (buffer);

  return 0;
}

__inline__ int proto_nmdc_user_say (user_t * u, buffer_t * b, buffer_t * message)
{
  bf_strcat (b, "<");
  bf_strcat (b, u->nick);
  bf_strcat (b, "> ");
  for (; message; message = message->next)
    bf_strncat (b, message->s, bf_used (message));
  if (*(b->e - 1) == '\n')
    b->e--;
  bf_strcat (b, "|");
  return 0;
}

__inline__ int proto_nmdc_user_say_pm (user_t * u, user_t * target, user_t * src, buffer_t * b,
				       buffer_t * message)
{

  bf_printf (b, "$To: %s From: %s $<%s> ", target->nick, u->nick, src->nick);
  for (; message; message = message->next)
    bf_strncat (b, message->s, bf_used (message));
  if (*(b->e - 1) == '\n')
    b->e--;
  if (b->e[-1] != '|')
    bf_strcat (b, "|");
  return 0;
}

__inline__ int proto_nmdc_user_say_string (user_t * u, buffer_t * b, unsigned char *message)
{
  bf_strcat (b, "<");
  bf_strcat (b, u->nick);
  bf_strcat (b, "> ");
  bf_strcat (b, message);
  if (*(b->e - 1) == '\n')
    b->e--;
  bf_strcat (b, "|");
  return 0;
}

int proto_nmdc_user_chat_all (user_t * u, buffer_t * message)
{
  buffer_t *buf;

  if (u->state == PROTO_STATE_DISCONNECTED)
    return 0;

  buf = bf_alloc (32 + NICKLENGTH + bf_size (message));

  proto_nmdc_user_say (u, buf, message);

  cache_queue (cache.chat, u, buf);

  bf_free (buf);

  return 0;
}

int proto_nmdc_user_send (user_t * u, user_t * target, buffer_t * message)
{
  buffer_t *buf;

  if (target->state == PROTO_STATE_DISCONNECTED)
    return EINVAL;

  buf = bf_alloc (32 + NICKLENGTH + bf_size (message));

  proto_nmdc_user_say (u, buf, message);

  cache_queue (((nmdc_user_t *) target->pdata)->privatemessages, u, buf);
  cache_count (privatemessages, target);
  target->MessageCnt++;
  target->CacheException++;

  bf_free (buf);

  return 0;
}

int proto_nmdc_user_send_direct (user_t * u, user_t * target, buffer_t * message)
{
  int retval = 0;
  buffer_t *buf;

  if (target->state == PROTO_STATE_DISCONNECTED)
    return EINVAL;

  buf = bf_alloc (32 + NICKLENGTH + bf_size (message));

  proto_nmdc_user_say (u, buf, message);

  retval = server_write (target->parent, buf);

  bf_free (buf);

  return retval;
}

int proto_nmdc_user_priv (user_t * u, user_t * target, user_t * source, buffer_t * message)
{
  buffer_t *buf;

  if (target->state == PROTO_STATE_DISCONNECTED)
    return 0;

  buf = bf_alloc (32 + 3 * NICKLENGTH + bf_size (message));

  proto_nmdc_user_say_pm (u, target, source, buf, message);

  if (target->state == PROTO_STATE_VIRTUAL) {
    plugin_send_event (target->plugin_priv, PLUGIN_EVENT_PM_IN, buf);
    goto leave;
  }

  cache_queue (((nmdc_user_t *) target->pdata)->privatemessages, u, buf);
  cache_count (privatemessages, target);

  target->MessageCnt++;
  target->CacheException++;

leave:
  bf_free (buf);

  return 0;
}

int proto_nmdc_user_priv_direct (user_t * u, user_t * target, user_t * source, buffer_t * message)
{
  int retval = 0;
  buffer_t *buf;

  if (target->state == PROTO_STATE_DISCONNECTED)
    return 0;

  buf = bf_alloc (32 + 3 * NICKLENGTH + bf_size (message));

  proto_nmdc_user_say_pm (u, target, source, buf, message);

  if (target->state == PROTO_STATE_VIRTUAL) {
    plugin_send_event (target->plugin_priv, PLUGIN_EVENT_PM_IN, buf);
    goto leave;
  }

  retval = server_write (target->parent, buf);

leave:
  bf_free (buf);

  return retval;
}

int proto_nmdc_user_raw (user_t * target, buffer_t * message)
{
  buffer_t *buf;

  if (target->state == PROTO_STATE_DISCONNECTED)
    return EINVAL;

  if (target->state == PROTO_STATE_VIRTUAL)
    return 0;

  buf = bf_copy (message, 0);

  cache_queue (((nmdc_user_t *) target->pdata)->privatemessages, target, buf);
  cache_count (privatemessages, target);

  target->MessageCnt++;
  target->CacheException++;

  bf_free (buf);

  return 0;
}

int proto_nmdc_user_raw_all (buffer_t * message)
{
  buffer_t *buf;

  buf = bf_copy (message, 0);

  cache_queue (cache.chat, HubSec, buf);

  bf_free (buf);

  return 0;
}

int proto_nmdc_user_userip2 (user_t * target)
{
  int retval;
  buffer_t *buf;
  struct in_addr addr;

  if (target->state == PROTO_STATE_DISCONNECTED)
    return EINVAL;

  buf = bf_alloc (128);

  addr.s_addr = target->ipaddress;
  bf_printf (buf, "$UserIP %s %s|", target->nick, inet_ntoa (addr));

  retval = server_write (target->parent, buf);

  bf_free (buf);

  return retval;
}

/******************************************************************************\
**                                                                            **
**                             USER HANDLING                                  **
**                                                                            **
\******************************************************************************/

user_t *proto_nmdc_user_alloc (void *priv)
{
  user_t *user;

  /* do we have a connect token? */
  if (!get_token (&rates.connects, &connects, now.tv_sec)) {
    proto_nmdc_warn (&now, "Users refused because of login rate.");
    return NULL;
  }

  /* yes, create and init user */
  user = malloc (sizeof (user_t) + sizeof (nmdc_user_t));
  if (!user)
    return NULL;
  memset (user, 0, sizeof (user_t) + sizeof (nmdc_user_t));

  /* protocol private data */
  user->pdata = ((void *) user) + sizeof (user_t);

  user->tthlist = tth_list_alloc (researchmaxcount);

  user->state = PROTO_STATE_INIT;
  user->parent = priv;

  init_bucket (&user->rate_warnings, now.tv_sec);
  init_bucket (&user->rate_violations, now.tv_sec);
  init_bucket (&user->rate_chat, now.tv_sec);
  init_bucket (&user->rate_search, now.tv_sec);
  init_bucket (&user->rate_myinfo, now.tv_sec);
  init_bucket (&user->rate_myinfoop, now.tv_sec);
  init_bucket (&user->rate_getnicklist, now.tv_sec);
  init_bucket (&user->rate_getinfo, now.tv_sec);
  init_bucket (&user->rate_downloads, now.tv_sec);

  /* warnings and violationss start with a full token load ! */
  user->rate_warnings.tokens = rates.warnings.burst;
  user->rate_violations.tokens = rates.violations.burst;

  /* init timer */
  etimer_init (&user->timer, (etimer_handler_t *) proto_nmdc_handle_timeout, user);

  /* add user to the list... */
  user->next = userlist;
  if (user->next)
    user->next->prev = user;
  user->prev = NULL;

  userlist = user;

  nmdc_stats.userjoin++;

  return user;
}

int proto_nmdc_user_free (user_t * user)
{
  ASSERT (!user->timer.tovalid);

  /* remove from the current user list */
  if (user->next)
    user->next->prev = user->prev;

  if (user->prev) {
    user->prev->next = user->next;
  } else {
    userlist = user->next;
  };

  user->parent = NULL;

  /* if the user was online, put him in the cachelist. if he was kicked, don't. */
  if ((!(user->flags & NMDC_FLAG_WASONLINE)) || (user->flags & NMDC_FLAG_WASKICKED)) {
    nicklistcache_deluser (user);
    proto_nmdc_user_freelist_add (user);
  } else {
    proto_nmdc_user_cachelist_add (user);
  }

  nmdc_stats.userpart++;

  NICKLISTCACHE_VERIFY;

  return 0;
}


user_t *proto_nmdc_user_find (unsigned char *nick)
{
  return hash_find_nick (&hashlist, nick, strlen (nick));
}

int proto_nmdc_user_disconnect (user_t * u, char *reason)
{
  buffer_t *buf;

  if (u->state == PROTO_STATE_DISCONNECTED)
    return 0;

  if (!u->plugin_priv) {
    buffer_t *b = bf_alloc (256 + strlen (reason));

    if (b) {
      bf_printf (b, "Nick %s, State %d, Reason: %s\n", u->nick, u->state, reason);
      plugin_send_event (NULL, PLUGIN_EVENT_DISCONNECT, b);
      bf_free (b);
    }
  } else {
    plugin_send_event (u->plugin_priv, PLUGIN_EVENT_DISCONNECT, bf_buffer (reason));
  }

  /* cancel the protocol timers */
  etimer_cancel (&u->timer);

  /* if user was online, clear out all stale data */
  if (u->state == PROTO_STATE_ONLINE) {
    string_list_purge (&cache.myinfo.messages, u);
    string_list_purge (&cache.myinfoupdate.messages, u);
    string_list_purge (&cache.myinfoupdateop.messages, u);
    string_list_purge (&cache.asearch.messages, u);
    string_list_purge (&cache.psearch.messages, u);
    string_list_clear (&((nmdc_user_t *) u->pdata)->results.messages);
    string_list_clear (&((nmdc_user_t *) u->pdata)->privatemessages.messages);

    plugin_send_event (u->plugin_priv, PLUGIN_EVENT_LOGOUT, NULL);

    hash_deluser (&hashlist, &u->hash);

    /* if the user was regged, log his ip */
    if (u->flags & PROTO_FLAG_REGISTERED) {
      account_t *a;

      a = account_find (u->nick);
      if (a)
	a->lastip = u->ipaddress;
    }

    /* mark user offline so the verifies don't fail. */
    u->state = PROTO_STATE_DISCONNECTED;

    /* do neither for hidden users */
    if (!(u->rights & CAP_HIDDEN)) {
      /* kicked users do not go on the cachehashlist */
      if (u->flags & NMDC_FLAG_WASKICKED) {
	nicklistcache_deluser (u);
	buf = bf_alloc (8 + NICKLENGTH);
	bf_strcat (buf, "$Quit ");
	bf_strcat (buf, u->nick);
	cache_queue (cache.myinfo, NULL, buf);
	cache_queue (cache.myinfoupdateop, NULL, buf);
	bf_free (buf);
      } else {
	hash_adduser (&cachehashlist, u);
	u->flags |= NMDC_FLAG_WASONLINE;
      }
    }
  } else {
    /* if the returned user has same nick, but different user pointer, this is legal */
    ASSERT (u != hash_find_nick (&hashlist, u->nick, strlen (u->nick)));
    u->state = PROTO_STATE_DISCONNECTED;
  }

  if (u->supports & NMDC_SUPPORTS_ZLine)
    cache.ZlineSupporters--;
  if (u->supports & NMDC_SUPPORTS_ZPipe)
    cache.ZpipeSupporters--;

  u->state = PROTO_STATE_DISCONNECTED;

  return 0;
}


int proto_nmdc_user_forcemove (user_t * u, unsigned char *destination, buffer_t * message)
{
  buffer_t *b;

  if (u->state == PROTO_STATE_DISCONNECTED)
    return 0;

  DPRINTF ("Redirecting user %s to %s because %.*s\n", u->nick, destination,
	   (int) bf_used (message), message->s);

  if (u->MessageCnt)
    proto_nmdc_user_flush (u);

  b = bf_alloc (265 + NICKLENGTH + strlen (destination) + bf_used (message));

  if (message)
    proto_nmdc_user_say (HubSec, b, message);

  if (destination && *destination) {
    bf_strcat (b, "$ForceMove ");
    bf_strcat (b, destination);
    bf_strcat (b, "|");
  }

  server_write (u->parent, b);
  bf_free (b);

  u->flags |= NMDC_FLAG_WASKICKED;

  if (u->state != PROTO_STATE_DISCONNECTED)
    server_disconnect_user (u->parent, "User forcemoved.");

  nmdc_stats.forcemove++;

  return 0;
}

int proto_nmdc_user_drop (user_t * u, buffer_t * message)
{
  buffer_t *b;

  if (u->state == PROTO_STATE_DISCONNECTED)
    return 0;

  if (u->MessageCnt)
    proto_nmdc_user_flush (u);

  if (message) {
    b = bf_alloc (265 + bf_used (message));

    proto_nmdc_user_say (HubSec, b, message);

    server_write (u->parent, b);
    bf_free (b);
  }

  u->flags |= NMDC_FLAG_WASKICKED;

  server_disconnect_user (u->parent, "User dropped");

  nmdc_stats.disconnect++;

  return 0;
}

int proto_nmdc_user_redirect (user_t * u, buffer_t * message)
{
  buffer_t *b;

  if (u->state == PROTO_STATE_DISCONNECTED)
    return 0;

  /* call plugin first. it can do custom redirects */
  if (plugin_send_event (u->plugin_priv, PLUGIN_EVENT_REDIRECT, message) != PLUGIN_RETVAL_CONTINUE) {
    return 0;
  }

  if (u->MessageCnt)
    proto_nmdc_user_flush (u);

  b = bf_alloc (265 + NICKLENGTH + strlen (config.Redirect) + bf_used (message));

  if (message)
    proto_nmdc_user_say (HubSec, b, message);

  if (config.Redirect && *config.Redirect) {
    bf_strcat (b, "$ForceMove ");
    bf_strcat (b, config.Redirect);
    bf_strcat (b, "|");
  }

  u->flags |= NMDC_FLAG_WASKICKED;

  server_write (u->parent, b);
  bf_free (b);

  if (u->state != PROTO_STATE_DISCONNECTED)
    server_disconnect_user (u->parent, "User redirected");

  nmdc_stats.redirect++;

  return 0;
}

int proto_nmdc_violation (user_t * u, struct timeval *now, char *reason)
{
  buffer_t *buf, *report;
  struct in_addr addr;

  /* if there are still tokens left, just return */
  if (get_token (&rates.violations, &u->rate_violations, now->tv_sec))
    return 0;

  /* never do this for owners! */
  if (u->rights & CAP_OWNER)
    return 0;

  /* user is in violation */

  /* if he is only a short time online, this is most likely a spammer and he will be hardbanned */
  buf = bf_alloc (128);
  if ((u->joinstamp - now->tv_sec) < config.ProbationPeriod) {
    bf_printf (buf, _("Rate Probation Violation (Last: %s)."), reason);
    banlist_add (&hardbanlist, HubSec->nick, u->nick, u->ipaddress, 0xFFFFFFFF, buf, 0);

  } else {
    bf_printf (buf, _("Rate Violation (Last: %s)."), reason);
    banlist_add (&hardbanlist, HubSec->nick, u->nick, u->ipaddress, 0xFFFFFFFF, buf,
		 now->tv_sec + config.ViolationBantime);
  }

  u->flags |= NMDC_FLAG_WASKICKED;

  /* send message */
  server_write (u->parent, buf);

  /* disconnect the user */
  if (u->state != PROTO_STATE_DISCONNECTED)
    server_disconnect_user (u->parent, buf->s);

  nmdc_stats.userviolate++;

  report = bf_alloc (1024);

  addr.s_addr = u->ipaddress;
  bf_printf (report, _("Flood detected: %s (%s) was banned: %.*s (Last violation: %s)\n"), u->nick,
	     inet_ntoa (addr), bf_used (buf), buf->s, reason);

  plugin_report (report);

  bf_free (report);
  bf_free (buf);

  return -1;
}

int proto_nmdc_user_warn (user_t * u, struct timeval *now, unsigned char *message, ...)
{
  buffer_t *buf;
  va_list ap;

  if (!get_token (&rates.warnings, &u->rate_warnings, now->tv_sec)) {
    return 0;
  }

  buf = bf_alloc (10240);

  bf_printf (buf, "<%s> ", HubSec->nick);
  bf_printf (buf, _("WARNING: "));

  va_start (ap, message);
  bf_vprintf (buf, message, ap);
  va_end (ap);

  bf_strcat (buf, "|");

  server_write (u->parent, buf);

  bf_free (buf);

  return 1;
}

int proto_nmdc_warn (struct timeval *now, unsigned char *message, ...)
{
  user_t *u;
  buffer_t *buf;
  va_list ap;

  if (!get_token (&rates.warnings, &rate_warnings, now->tv_sec))
    return 0;

  u = hash_find_nick (&hashlist, config.SysReportTarget, strlen (config.SysReportTarget));
  if (!u)
    return 0;

  buf = bf_alloc (10240);

  bf_printf (buf, _("WARNING: "));

  va_start (ap, message);
  bf_vprintf (buf, message, ap);
  va_end (ap);

  proto_nmdc_user_priv_direct (HubSec, u, HubSec, buf);

  bf_free (buf);

  return 1;
}


int proto_nmdc_handle_input (user_t * user, buffer_t ** buffers)
{
  buffer_t *b;

  if (!buffers) {
    etimer_set (&user->timer, PROTO_TIMEOUT_ONLINE);
    return 0;
  }

  if (bf_size (*buffers) > MAX_TOKEN_SIZE) {
    bf_free (*buffers);
    *buffers = NULL;
    return 0;
  }

  for (;;) {
    /* get a new token */
    b = bf_sep_char (buffers, '|');
    if (!b)
      break;

    /* process it and free memory */
    errno = 0;			/* make sure this is reset otherwise errno check will cause crashes */
    if (proto_nmdc_handle_token (user, b) < 0) {
      /* This should never happen! On an EPIPE, server_write should do this.
         if (errno == EPIPE)
         server_disconnect_user (user->parent, "EPIPE");
       */
      ASSERT (!((errno == EPIPE) && user->parent));
      bf_free (b);
      break;
    }
    bf_free (b);
    /* if parent is freed "buffers" is not longer valid */
    if (user->state == PROTO_STATE_DISCONNECTED)
      break;

    gettime ();
  }

  proto_nmdc_user_freelist_clear ();

  return 0;
}

/******************************************************************************\
**                                                                            **
**                                timerout handling                           **
**                                                                            **
\******************************************************************************/

unsigned long proto_nmdc_handle_timeout (user_t * user)
{
  if (user->state == PROTO_STATE_ONLINE) {
    /* online users never time out. */
    if (notimeout)
      return 0;

    /* reset the timer if the user is not buffering */
    if (!server_isbuffering (user->parent))
      return etimer_set (&user->timer, PROTO_TIMEOUT_ONLINE);
  }

  return server_disconnect_user (user->parent, "Protocol Timeout");
}

/******************************************************************************\
**                                                                            **
**                                Nicklist char handling                      **
**                                                                            **
\******************************************************************************/

void nmdc_nickchar_rebuild ()
{
  unsigned char *c = nickchars;

  if (!c || !*c) {
    /* accept all chars */
    memset (nickchar_map, 1, sizeof (nickchar_map));
    return;
  }

  memset (nickchar_map, 0, sizeof (nickchar_map));

  for (; *c; c++)
    nickchar_map[*c] = 1;
}

unsigned long nmdc_event_config (plugin_user_t * user, void *dummy, unsigned long event,
				 config_element_t * elem)
{
  if (elem == cfg_nickchars)
    nmdc_nickchar_rebuild ();

  return PLUGIN_RETVAL_CONTINUE;
}


/******************************************************************************\
**                                                                            **
**                                INIT HANDLING                               **
**                                                                            **
\******************************************************************************/

int proto_nmdc_init ()
{
  unsigned int i, l;
  unsigned char *s, *d;
  unsigned char lock[16 + sizeof (LOCK) + 2 + LOCKLENGTH + 2 + 1];
  struct timeval now;

  /* prepare lock calculation shortcut */
  strcpy (lock, "EXTENDEDPROTOCOL");
  strcat (lock, LOCK);
  strcat (lock, "[[");
  l = strlen (lock);
  keyoffset = l;
  for (i = 0; i < LOCKLENGTH; i++, l++)
    lock[l] = '\0';
  lock[l++] = ']';
  lock[l++] = ']';
  lock[l] = '\0';

  ASSERT (l <= sizeof (lock));

  memset (key, 0, sizeof (key));
  s = lock;
  d = key;
  for (i = 1; i < l; i++) {
    d[i] = s[i] ^ s[i - 1];
  };

  d[0] = s[0] ^ d[l - 1] ^ 5;

  for (i = 0; i < l; i++)
    d[i] = ((d[i] << 4) & 240) | ((d[i] >> 4) & 15);

  keylen = l;

  /* rate limiting stuff */
  memset ((void *) &rates, 0, sizeof (ratelimiting_t));
  init_bucket_type (&rates.chat, 2, 3, 1);
  init_bucket_type (&rates.asearch, 15, 5, 1);
  init_bucket_type (&rates.psearch, 15, 5, 1);
  init_bucket_type (&rates.myinfo, 1800, 1, 1);
  init_bucket_type (&rates.myinfoop, 120, 1, 1);
  init_bucket_type (&rates.getnicklist, 1200, 1, 1);
  init_bucket_type (&rates.getinfo, 1, 10, 10);
  init_bucket_type (&rates.downloads, 5, 6, 1);
  init_bucket_type (&rates.connects, 1, 10, 10);
  init_bucket_type (&rates.psresults_in, 15, 100, 25);
  init_bucket_type (&rates.psresults_out, 15, 50, 25);
  init_bucket_type (&rates.warnings, 120, 10, 1);
  init_bucket_type (&rates.violations, 20, 10, 3);

  config_register ("rate.chat.period", CFG_ELEM_ULONG, &rates.chat.period,
		   _
		   ("Period of chat messages. This controls how often a user can send a chat message. Keep this low."));
  config_register ("rate.chat.burst", CFG_ELEM_ULONG, &rates.chat.burst,
		   _
		   ("Burst of chat messages. This controls how many chat messages a user can 'save up'. Keep this low."));
  config_register ("rate.activesearch.period", CFG_ELEM_ULONG, &rates.asearch.period,
		   _
		   ("Period of searches. This controls how often an active user can search. Keep this reasonable."));
  config_register ("rate.activesearch.burst", CFG_ELEM_ULONG, &rates.asearch.burst,
		   _
		   ("Burst of searches. This controls how many searches an active user can 'save up'. Keep this low."));
  config_register ("rate.passivesearch.period", CFG_ELEM_ULONG, &rates.psearch.period,
		   _
		   ("Period of searches. This controls how often a passive user can search. Keep this reasonable."));
  config_register ("rate.passivesearch.burst", CFG_ELEM_ULONG, &rates.psearch.burst,
		   _
		   ("Burst of searches. This controls how many searches a passive user can 'save up'. Keep this low."));
  config_register ("rate.myinfo.period", CFG_ELEM_ULONG, &rates.myinfo.period,
		   _
		   ("Period of MyINFO messages. This controls how often a user can send a MyINFO message that is send to everyone. Keep this very high."));
  config_register ("rate.myinfo.burst", CFG_ELEM_ULONG, &rates.myinfo.burst,
		   _
		   ("Burst of MyINFO messages. This controls how many MyINFO messages a user can 'save up' (everyone). Keep this at 1."));
  config_register ("rate.myinfoop.period", CFG_ELEM_ULONG, &rates.myinfoop.period,
		   _
		   ("Period of MyINFO messages. This controls how often a user can send a MyINFO message that is send on to the ops only. Keep this very high."));
  config_register ("rate.myinfoop.burst", CFG_ELEM_ULONG, &rates.myinfoop.burst,
		   _
		   ("Burst of MyINFO messages. This controls how many MyINFO messages a user can 'save up' (OPs messages only). Keep this at 1."));
  config_register ("rate.getnicklist.period", CFG_ELEM_ULONG, &rates.getnicklist.period,
		   _
		   ("Period of nicklist requests. This controls how often a user can refresh his userlist. Keep this high."));
  config_register ("rate.getnicklist.burst", CFG_ELEM_ULONG, &rates.getnicklist.burst,
		   _
		   ("Burst of nicklist requests. This controls how many userlist refreshes a user can 'save up'. Keep this at 1."));
  config_register ("rate.getinfo.period", CFG_ELEM_ULONG, &rates.getinfo.period,
		   _
		   ("Period of getinfo requests. This controls how often a user can request info on a user. Keep this low."));
  config_register ("rate.getinfo.burst", CFG_ELEM_ULONG, &rates.getinfo.burst,
		   _
		   ("Burst of getinfo requests. This controls how many getinfo requests a user can 'save up'."));
  config_register ("rate.download.period", CFG_ELEM_ULONG, &rates.downloads.period,
		   _
		   ("Period of downloads. This controls how often a user can initiate a download. Keep this low."));
  config_register ("rate.download.burst", CFG_ELEM_ULONG, &rates.downloads.burst,
		   _
		   ("Burst of downloads. This controls how many downloads a user can 'save up'. Keep this reasonable."));
  config_register ("rate.connect.period", CFG_ELEM_ULONG, &rates.connects.period,
		   _
		   ("Period of connects. This controls how often the connect counter is refreshed. Keep this low."));
  config_register ("rate.connect.burst", CFG_ELEM_ULONG, &rates.connects.burst,
		   _
		   ("Burst of connects. This controls how many new user connects can be saved up in idle time. Keep this low."));
  config_register ("rate.connect.refill", CFG_ELEM_ULONG, &rates.connects.refill,
		   _
		   ("Refill of connects. This controls how many new user connects are added each time the counter resets. Keep this low."));

  config_register ("rate.results_in.period", CFG_ELEM_ULONG, &rates.psresults_in.period,
		   _
		   ("Period of passive search results. This controls how often the incoming passive search results counter is refreshed. Keep this low."));
  config_register ("rate.results_in.burst", CFG_ELEM_ULONG, &rates.psresults_in.burst,
		   _
		   ("Burst of passive search results. This controls how many incoming passive search results can be saved up in idle time. Keep this equal to the search period."));
  config_register ("rate.results_in.refill", CFG_ELEM_ULONG, &rates.psresults_in.refill,
		   _
		   ("Refill of passive search results. This controls how many incoming passive search results are added each time the counter resets. Keep this low."));

  config_register ("rate.results_out.period", CFG_ELEM_ULONG, &rates.psresults_out.period,
		   _
		   ("Period of passive search results. This controls how often the outgoing passive search results counter is refreshed. Keep this low."));
  config_register ("rate.results_out.burst", CFG_ELEM_ULONG, &rates.psresults_out.burst,
		   _
		   ("Burst of passive search results. This controls how many outgoing passive search results can be saved up in idle time. Keep this reasonably high."));
  config_register ("rate.results_out.refill", CFG_ELEM_ULONG, &rates.psresults_out.refill,
		   _
		   ("Refill of passive search results. This controls how many outgoing passive search results are added each time the counter resets. Keep this reasonably high."));

  config_register ("rate.warnings.period", CFG_ELEM_ULONG, &rates.warnings.period,
		   _
		   ("Period of user warnings. This controls how often a warning is send to user that overstep limits."));
  config_register ("rate.warnings.refill", CFG_ELEM_ULONG, &rates.warnings.refill,
		   _
		   ("Refill of user warnings. This controls how many warning a user gets within the period."));
  config_register ("rate.warnings.burst", CFG_ELEM_ULONG, &rates.warnings.burst,
		   _
		   ("Burst of user warnings. This controls how many warnings a user that overstep limits can save up."));

  config_register ("rate.violations.period", CFG_ELEM_ULONG, &rates.violations.period,
		   _
		   ("Period of user violations. This controls how often a warning is send to user that overstep limits."));
  config_register ("rate.violations.refill", CFG_ELEM_ULONG, &rates.violations.refill,
		   _
		   ("Refill of user violations. This controls how many warning a user gets within the period."));
  config_register ("rate.violations.burst", CFG_ELEM_ULONG, &rates.violations.burst,
		   _
		   ("Burst of user violations. This controls how many violations a user that overstep limits can save up."));

  /* cache stuff */
  memset ((void *) &cache, 0, sizeof (cache_t));
  cache.needrebuild = 1;

  init_bucket_type (&cache.chat.timertype, 1, 1, 1);
  init_bucket_type (&cache.myinfo.timertype, 1, 1, 1);
  init_bucket_type (&cache.myinfoupdate.timertype, 1, 1, 1);	/* every 5 minutes */
  init_bucket_type (&cache.myinfoupdateop.timertype, 1, 1, 1);
  init_bucket_type (&cache.asearch.timertype, 1, 1, 1);
  init_bucket_type (&cache.psearch.timertype, 1, 1, 1);
  init_bucket_type (&cache.aresearch.timertype, 1, 1, 1);
  init_bucket_type (&cache.presearch.timertype, 1, 1, 1);
  init_bucket_type (&cache.results.timertype, 1, 1, 1);
  init_bucket_type (&cache.privatemessages.timertype, 1, 1, 1);

  gettimeofday (&now, NULL);

  init_bucket (&cache.chat.timer, now.tv_sec);
  init_bucket (&cache.myinfo.timer, now.tv_sec);
  init_bucket (&cache.myinfoupdate.timer, now.tv_sec);
  init_bucket (&cache.myinfoupdateop.timer, now.tv_sec);
  init_bucket (&cache.asearch.timer, now.tv_sec);
  init_bucket (&cache.psearch.timer, now.tv_sec);
  init_bucket (&cache.aresearch.timer, now.tv_sec);
  init_bucket (&cache.presearch.timer, now.tv_sec);
  init_bucket (&cache.results.timer, now.tv_sec);
  init_bucket (&cache.privatemessages.timer, now.tv_sec);

/* FIXME this should be removed entirely.
  config_register ("cache.chat.period", CFG_ELEM_ULONG, &cache.chat.timertype.period,
		   _
		   ("Period of chat cache flush. This controls how often chat messages are sent to users. Keep this low."));
  config_register ("cache.join.period", CFG_ELEM_ULONG, &cache.myinfo.timertype.period,
		   _
		   ("Period of join cache flush. This controls how often users are notified of new joins."));
  config_register ("cache.update.period", CFG_ELEM_ULONG, &cache.myinfoupdate.timertype.period,
		   _
		   ("Period of update cache flush. This controls how often users are sent MyINFO updates. Keep this high."));
  config_register ("cache.updateop.period", CFG_ELEM_ULONG, &cache.myinfoupdateop.timertype.period,
		   _
		   ("Period of operator update cache flush. This controls how often operators are sent MyINFO updates. Keep this low."));
  config_register ("cache.activesearch.period", CFG_ELEM_ULONG, &cache.asearch.timertype.period,
		   _
		   ("Period of active search cache flush. This controls how often search messages are sent to active users."));
  config_register ("cache.passivesearch.period", CFG_ELEM_ULONG, &cache.psearch.timertype.period,
		   _
		   ("Period of passive search cache flush. This controls how often search messages are sent to passive users."));
  config_register ("cache.results.period", CFG_ELEM_ULONG, &cache.results.timertype.period,
		   _
		   ("Period of search results cache flush. This controls how often search results are sent to passive users."));
  config_register ("cache.pm.period", CFG_ELEM_ULONG, &cache.privatemessages.timertype.period,
		   _
		   ("Period of private messages cache flush. This controls how often private messages are sent to users. Keep this low."));

  config_register ("cache.activeresearch.period", CFG_ELEM_ULONG, &cache.aresearch.timertype.period,
		   _
		   ("Period of active repeated search cache flush. This controls how often search messages are sent to active users."));
  config_register ("cache.passiveresearch.period", CFG_ELEM_ULONG,
		   &cache.presearch.timertype.period,
		   _
		   ("Period of passive repeated search cache flush. This controls how often search messages are sent to passive users."));
*/

  cloning = DEFAULT_CLONING;
  chatmaxlength = DEFAULT_MAXCHATLENGTH;
  searchmaxlength = DEFAULT_MAXSEARCHLENGTH;
  srmaxlength = DEFAULT_MAXSRLENGTH;
  researchmininterval = DEFAULT_RESEARCH_MININTERVAL;
  researchperiod = DEFAULT_RESEARCH_PERIOD;
  researchmaxcount = DEFAULT_RESEARCH_MAXCOUNT;
  defaultbanmessage = strdup ("");
  nickchars = strdup (DEFAULT_NICKCHARS);

  config_register ("hub.allowcloning", CFG_ELEM_UINT, &cloning,
		   _("Allow multiple users from the same IP address."));
  config_register ("nmdc.maxchatlength", CFG_ELEM_UINT, &chatmaxlength,
		   _("Maximum length of a chat message."));
  config_register ("nmdc.maxsearchlength", CFG_ELEM_UINT, &searchmaxlength,
		   _("Maximum length of a search message."));
  config_register ("nmdc.maxsrlength", CFG_ELEM_UINT, &srmaxlength,
		   _("Maximum length of a search result"));

  config_register ("nmdc.researchinterval", CFG_ELEM_UINT, &researchmininterval,
		   _("Minimum time before a re-search is considered valid."));
  config_register ("nmdc.researchperiod", CFG_ELEM_UINT, &researchperiod,
		   _("Period during which a search is considered a re-search."));
  config_register ("nmdc.researchmaxcount", CFG_ELEM_UINT, &researchmaxcount,
		   _("Maximum number of searches cached."));

  config_register ("nmdc.defaultbanmessage", CFG_ELEM_STRING, &defaultbanmessage,
		   _("This message is send to all banned users when they try to join."));

  config_register ("nmdc.notimeoutonline", CFG_ELEM_UINT, &notimeout,
		   _("Online users never get timed out."));

  cfg_nickchars = config_register ("nmdc.nickchars", CFG_ELEM_STRING, &nickchars,
				   _
				   ("These are the characters allowed in a nick. An empty string means all characters. Does NOT support utf-8 character."));

  /* further inits */
  memset (&hashlist, 0, sizeof (hashlist));
  hash_init (&hashlist);
  hash_init (&cachehashlist);
  token_init ();
  init_bucket (&rate_warnings, now.tv_sec);
  rate_warnings.tokens = rates.warnings.burst;

  memset (&nmdc_stats, 0, sizeof (nmdc_stats_t));

  banlist_init (&reconnectbanlist);

  memset (nmdc_forbiddenchars, 1, sizeof (nmdc_forbiddenchars));
  nmdc_forbiddenchars[' '] = 0;
  nmdc_forbiddenchars['\0'] = 0;
  nmdc_forbiddenchars['\n'] = 0;
  nmdc_forbiddenchars['\t'] = 0;

  /* *INDENT-OFF* */
  stats_register ("nmdc.cacherebuild",		VAL_ELEM_ULONG, &nmdc_stats.cacherebuild,  "rebuild of nick list cache.");
  stats_register ("nmdc.userjoin",		VAL_ELEM_ULONG, &nmdc_stats.userjoin, 	   "all user joins.");
  stats_register ("nmdc.userpart",		VAL_ELEM_ULONG, &nmdc_stats.userpart,      "all user parts.");
  stats_register ("nmdc.userviolate",		VAL_ELEM_ULONG, &nmdc_stats.userviolate,   "all user that are kicked for rate violations.");
  stats_register ("nmdc.banned",		VAL_ELEM_ULONG, &nmdc_stats.banned,        "all forcemoves  for banned users.");
  stats_register ("nmdc.forcemove",		VAL_ELEM_ULONG, &nmdc_stats.forcemove,     "all forcemoves.");
  stats_register ("nmdc.disconnect",		VAL_ELEM_ULONG, &nmdc_stats.disconnect,    "all drops/disconnects.");
  stats_register ("nmdc.redirect",		VAL_ELEM_ULONG, &nmdc_stats.redirect,      "all redirects.");
  stats_register ("nmdc.tokens",		VAL_ELEM_ULONG, &nmdc_stats.tokens, 	   "all tokens processed.");
  stats_register ("nmdc.brokenkey",		VAL_ELEM_ULONG, &nmdc_stats.brokenkey,     "all users refused cuz of broken key.");
  stats_register ("nmdc.badnick",		VAL_ELEM_ULONG, &nmdc_stats.badnick,       "all users refused cuz of illegal chars in nickname.");
  stats_register ("nmdc.usednick",		VAL_ELEM_ULONG, &nmdc_stats.usednick,      "all users refused cuz of nickname already used.");
  stats_register ("nmdc.mynick",		VAL_ELEM_ULONG, &nmdc_stats.mynick,        "all CTM exploit IPs that have been banned.");
  stats_register ("nmdc.softban",		VAL_ELEM_ULONG, &nmdc_stats.softban,       "banned users that tried to log in.");
  stats_register ("nmdc.nickban",		VAL_ELEM_ULONG, &nmdc_stats.nickban,       "users banned by nick.");
  stats_register ("nmdc.badpasswd",		VAL_ELEM_ULONG, &nmdc_stats.badpasswd,     "bad password");
  stats_register ("nmdc.notags",		VAL_ELEM_ULONG, &nmdc_stats.notags,        "refused users without tags");
  stats_register ("nmdc.badmyinfo",		VAL_ELEM_ULONG, &nmdc_stats.badmyinfo,     "users that had corrupt MyINFOs");
  stats_register ("nmdc.preloginevent",		VAL_ELEM_ULONG, &nmdc_stats.preloginevent, "user dropped by plugins before login.");
  stats_register ("nmdc.loginevent",		VAL_ELEM_ULONG, &nmdc_stats.loginevent,    "users dropped by plugins after login.");
  stats_register ("nmdc.logincached",		VAL_ELEM_ULONG, &nmdc_stats.logincached,   "users that rejoined within hub.delayedlogout");
  stats_register ("nmdc.chatoverflow",		VAL_ELEM_ULONG, &nmdc_stats.chatoverflow,  "when a user oversteps his chat allowence");
  stats_register ("nmdc.chatfakenick",		VAL_ELEM_ULONG, &nmdc_stats.chatfakenick,  "when a user fakes his source nick");
  stats_register ("nmdc.chattoolong",		VAL_ELEM_ULONG, &nmdc_stats.chattoolong,   "chat messages that were dropped due to length");
  stats_register ("nmdc.chatevent",		VAL_ELEM_ULONG, &nmdc_stats.chatevent,     "chat messages dropped by plugins");
  stats_register ("nmdc.myinfooverflow",	VAL_ELEM_ULONG, &nmdc_stats.myinfooverflow,"user that oversteps myinfo rate");
  stats_register ("nmdc.myinfoevent",		VAL_ELEM_ULONG, &nmdc_stats.myinfoevent,   "myinfo that is dropped by plugins");
  stats_register ("nmdc.searchoverflow",	VAL_ELEM_ULONG, &nmdc_stats.searchoverflow,"user that oversteps the searchrate");
  stats_register ("nmdc.searchcorrupt",		VAL_ELEM_ULONG, &nmdc_stats.searchcorrupt, "user send an invalid search messages");
  stats_register ("nmdc.searchevent",		VAL_ELEM_ULONG, &nmdc_stats.searchevent,   "search dropped by plugin");
  stats_register ("nmdc.searchtoolong",		VAL_ELEM_ULONG, &nmdc_stats.searchtoolong, "search message was too long");
  stats_register ("nmdc.researchdrop",		VAL_ELEM_ULONG, &nmdc_stats.researchdrop,  "search message repeated within nmdc.researchinterval");
  stats_register ("nmdc.researchmatch",		VAL_ELEM_ULONG, &nmdc_stats.researchmatch, "search message only send to part of the users.");
  stats_register ("nmdc.searchtth",		VAL_ELEM_ULONG, &nmdc_stats.searchtth,     "TTH search");
  stats_register ("nmdc.searchnormal",		VAL_ELEM_ULONG, &nmdc_stats.searchnormal,  "normal search");
  stats_register ("nmdc.sroverflow",		VAL_ELEM_ULONG, &nmdc_stats.sroverflow,    "search result rate overstepped");
  stats_register ("nmdc.srevent",		VAL_ELEM_ULONG, &nmdc_stats.srevent,       "search result droppped by plugin");
  stats_register ("nmdc.srrobot",		VAL_ELEM_ULONG, &nmdc_stats.srrobot,       "search result send to virtual user (chatrooms, hubsec,...)");
  stats_register ("nmdc.srtoolong",		VAL_ELEM_ULONG, &nmdc_stats.srtoolong,     "search result too long");
  stats_register ("nmdc.srfakesource",		VAL_ELEM_ULONG, &nmdc_stats.srfakesource,  "search result had a faked source");
  stats_register ("nmdc.srnodest",		VAL_ELEM_ULONG, &nmdc_stats.srnodest,      "search result for user that doesn't exist");
  stats_register ("nmdc.ctmoverflow",		VAL_ELEM_ULONG, &nmdc_stats.ctmoverflow,   "ctm rate overstepped");
  stats_register ("nmdc.ctmbadtarget",		VAL_ELEM_ULONG, &nmdc_stats.ctmbadtarget,  "ctm for user that doesn't exist");
  stats_register ("nmdc.rctmoverflow",		VAL_ELEM_ULONG, &nmdc_stats.rctmoverflow,  "rctm rate overstepped");
  stats_register ("nmdc.rctmbadtarget",		VAL_ELEM_ULONG, &nmdc_stats.rctmbadtarget, "rctm for user that doesn't exist");
  stats_register ("nmdc.rctmbadsource",		VAL_ELEM_ULONG, &nmdc_stats.rctmbadsource, "rctm with fake source");
  stats_register ("nmdc.pmoverflow",		VAL_ELEM_ULONG, &nmdc_stats.pmoverflow,    "privatemessage rate overstepped");
  stats_register ("nmdc.pmoutevent",		VAL_ELEM_ULONG, &nmdc_stats.pmoutevent,    "outgoing pm dropped by plugin");
  stats_register ("nmdc.pmbadtarget",		VAL_ELEM_ULONG, &nmdc_stats.pmbadtarget,   "pm for user that doesn't exist");
  stats_register ("nmdc.pmbadsource",		VAL_ELEM_ULONG, &nmdc_stats.pmbadsource,   "pm with faked source");
  stats_register ("nmdc.pminevent",		VAL_ELEM_ULONG, &nmdc_stats.pminevent,     "incoming pm dropped by plugin");
  stats_register ("nmdc.botinfo",		VAL_ELEM_ULONG, &nmdc_stats.botinfo,       "botinfo requested");
  stats_register ("nmdc.cache_quit",		VAL_ELEM_ULONG, &nmdc_stats.cache_quit,    "total bytes send in $Quit messages");
  stats_register ("nmdc.cache_myinfo",		VAL_ELEM_ULONG, &nmdc_stats.cache_myinfo,  "total bytes send in login myinfos");
  stats_register ("nmdc.cache_myinfoupdate",	VAL_ELEM_ULONG, &nmdc_stats.cache_myinfoupdate, "total bytes send in myinfo updates");
  stats_register ("nmdc.cache_chat",		VAL_ELEM_ULONG, &nmdc_stats.cache_chat,    "total bytes send in chat messages");
  stats_register ("nmdc.cache_asearch",		VAL_ELEM_ULONG, &nmdc_stats.cache_asearch, "total bytes send in active searches");
  stats_register ("nmdc.cache_psearch",		VAL_ELEM_ULONG, &nmdc_stats.cache_psearch, "total bytes send in passive searches");
  stats_register ("nmdc.cache_messages",	VAL_ELEM_ULONG, &nmdc_stats.cache_messages,"total bytes send in user message");
  stats_register ("nmdc.cache_results",		VAL_ELEM_ULONG, &nmdc_stats.cache_results, "total byte send in search results");

  stats_register ("nicklistcache_nicklist_length",  VAL_ELEM_ULONG, &cache.nicklist_length,  "current length of nicklist.");
  stats_register ("nicklistcache_oplist_length",    VAL_ELEM_ULONG, &cache.oplist_length,    "current length of oplist.");
  stats_register ("nicklistcache_infolist_length",  VAL_ELEM_ULONG, &cache.infolist_length,  "current length of infolist.");
  stats_register ("nicklistcache_hellolist_length", VAL_ELEM_ULONG, &cache.hellolist_length, "current length of hellolist.");

#ifdef ZLINES
  stats_register ("nicklistcache_infolistzline_length", VAL_ELEM_ULONG, &cache.infolistzline_length, "current length of infolistzline.");
  stats_register ("nicklistcache_nicklistzline_length", VAL_ELEM_ULONG, &cache.nicklistzline_length, "current length of nicklistzline.");
  stats_register ("nicklistcache_infolistzpipe_length", VAL_ELEM_ULONG, &cache.infolistzpipe_length, "current length of infolistzpipe.");
  stats_register ("nicklistcache_nicklistzpipe_length", VAL_ELEM_ULONG, &cache.nicklistzpipe_length, "current length of nicklistzpipe.");
#endif

  stats_register ("nicklistcache_infolistupdate_length", VAL_ELEM_ULONG, &cache.infolistupdate_length, "current length of infolist update.");

  stats_register ("nicklistcache_nicklist_count",  VAL_ELEM_ULONG, &cache.nicklist_count,  "current count of nicklist.");
  stats_register ("nicklistcache_oplist_count",    VAL_ELEM_ULONG, &cache.oplist_count,    "current count of oplist.");
  stats_register ("nicklistcache_infolist_count",  VAL_ELEM_ULONG, &cache.infolist_count,  "current count of infolist.");
  stats_register ("nicklistcache_hellolist_count", VAL_ELEM_ULONG, &cache.hellolist_count, "current count of hellolist.");

#ifdef ZLINES
  stats_register ("nicklistcache_infolistzline_count", VAL_ELEM_ULONG, &cache.infolistzline_count, "current count of infolistzline.");
  stats_register ("nicklistcache_nicklistzline_count", VAL_ELEM_ULONG, &cache.nicklistzline_count, "current count of nicklistzline.");
  stats_register ("nicklistcache_infolistzpipe_count", VAL_ELEM_ULONG, &cache.infolistzpipe_count, "current count of infolistzpipe.");
  stats_register ("nicklistcache_nicklistzpipe_count", VAL_ELEM_ULONG, &cache.nicklistzpipe_count, "current count of nicklistzpipe.");
#endif
  
  stats_register ("nicklistcache_infolistupdate_bytes", VAL_ELEM_ULONG, &cache.infolistupdate_bytes, "current bytes send in infolist updates.");

  /* *INDENT-ON* */

  return 0;
}

int proto_nmdc_setup ()
{

  HubSec = proto_nmdc_user_addrobot (config.HubSecurityNick, config.HubSecurityDesc);
  HubSec->flags |= PROTO_FLAG_HUBSEC;
  plugin_new_user ((void *) &HubSec->plugin_priv, HubSec, &nmdc_proto);

  plugin_nmdc = plugin_register ("nmdc");
  plugin_request (plugin_nmdc, PLUGIN_EVENT_CONFIG, (void *) &nmdc_event_config);

  nmdc_nickchar_rebuild ();

  return 0;
}
