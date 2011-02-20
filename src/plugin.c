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

#include "plugin_int.h"
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#ifndef __USE_W32_SOCKETS
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#endif

#include "aqtime.h"
#include "utils.h"
#include "banlist.h"
#include "user.h"
#include "core_config.h"
#include "hashlist_func.h"

unsigned char *ConfigFile;
unsigned char *HardBanFile;
unsigned char *SoftBanFile;
unsigned char *AccountsFile;

unsigned char *KickBanRedirect;

extern user_t *HubSec;
extern hashlist_t hashlist;
extern user_t *userlist;

plugin_manager_t *manager;
unsigned long pluginIDs;

flag_t plugin_supports[] = {
  {"NoGetINFO", 1, ""},
  {"NoHello", 2, ""},
  {"UserCommand", 4, ""},
  {"UserIP2", 8, ""},
  {"QuickList", 16, ""},
  {"TTHSearch", 32, ""},
  {NULL, 0, NULL}
};

/******************************* UTILITIES: REPORING **************************************/

int plugin_perror (unsigned char *format, ...)
{
  va_list ap;
  int retval;
  buffer_t *b;

  b = bf_alloc (1024);

  va_start (ap, format);
  bf_vprintf (b, format, ap);
  va_end (ap);

  if (errno)
    bf_printf (b, ": %s", strerror (errno));

  retval = plugin_report (b);

  bf_free (b);

  return retval;
}

int plugin_report (buffer_t * message)
{
  user_t *u;

  if (!*config.SysReportTarget)
    return EINVAL;

  u = hash_find_nick (&hashlist, config.SysReportTarget, strlen (config.SysReportTarget));

  if (!u)
    return EINVAL;

  return ((plugin_private_t *) u->plugin_priv)->proto->chat_priv (HubSec, u, HubSec, message);
}

/******************************* UTILITIES: USER MANAGEMENT **************************************/

int plugin_user_next (plugin_user_t ** user)
{
  user_t *u = *user ? ((plugin_private_t *) (*user)->private)->parent->next : userlist;

  while (u && (u->state != PROTO_STATE_ONLINE))
    u = u->next;

  *user = u ? &((plugin_private_t *) u->plugin_priv)->user : NULL;

  return (*user != NULL);
}

plugin_user_t *plugin_user_find (unsigned char *name)
{
  user_t *u;

  u = hash_find_nick (&hashlist, name, strlen (name));
  if (!u)
    return NULL;

  return &((plugin_private_t *) u->plugin_priv)->user;
}

plugin_user_t *plugin_user_find_ip (plugin_user_t * last, unsigned long ip)
{
  user_t *u = last ? ((plugin_private_t *) (last)->private)->parent : NULL;

  u = hash_find_ip_next (&hashlist, u, ip);
  if (!u)
    return NULL;

  return &((plugin_private_t *) u->plugin_priv)->user;
}

plugin_user_t *plugin_user_find_net (plugin_user_t * last, unsigned long ip, unsigned long netmask)
{
  user_t *u = last ? ((plugin_private_t *) (last)->private)->parent : NULL;

  u = hash_find_net_next (&hashlist, u, ip, netmask);
  if (!u)
    return NULL;

  return &((plugin_private_t *) u->plugin_priv)->user;
}

buffer_t *plugin_user_getmyinfo (plugin_user_t * user)
{
  return ((user_t *) ((plugin_private_t *) user->private)->parent)->MyINFO;
}

/******************************* UTILITIES: KICK/BAN **************************************/

int plugin_user_drop (plugin_user_t * user, buffer_t * message)
{
  user_t *u;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  return ((plugin_private_t *) user->private)->proto->user_drop (u, message);
}

int plugin_user_kick (plugin_user_t * op, plugin_user_t * user, buffer_t * message)
{
  user_t *u;
  buffer_t *b;
  unsigned int retval;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  banlist_add (&softbanlist, (op ? op->nick : HubSec->nick), u->nick, u->ipaddress, 0xffffffff,
	       message, now.tv_sec + config.defaultKickPeriod);

  b = bf_alloc (265 + bf_used (message));

  bf_printf (b, _("You have been kicked by %s because: %.*s\n"), (op ? op->nick : HubSec->nick),
	     bf_used (message), message->s);

  plugin_send_event (((plugin_private_t *) user->private), PLUGIN_EVENT_KICK, b);

  retval =
    ((plugin_private_t *) u->plugin_priv)->proto->user_forcemove (u, config.KickBanRedirect, b);

  bf_free (b);

  return retval;
}

int plugin_user_banip (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
		       unsigned long period)
{
  user_t *u;
  buffer_t *b;
  unsigned int retval;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  banlist_add (&softbanlist, (op ? op->nick : HubSec->nick), u->nick, u->ipaddress, 0xffffffff,
	       message, period ? now.tv_sec + period : 0);

  b = bf_alloc (265 + bf_used (message));

  bf_printf (b, _("You have been banned by %s because: %.*s\n"), (op ? op->nick : HubSec->nick),
	     bf_used (message), message->s);

  plugin_send_event (((plugin_private_t *) user->private), PLUGIN_EVENT_BAN, b);

  retval =
    ((plugin_private_t *) user->private)->proto->user_forcemove (u, config.KickBanRedirect, b);

  bf_free (b);

  return retval;
}

int plugin_user_unban (plugin_user_t * user)
{
  user_t *u;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  banlist_del_bynick (&softbanlist, u->nick);
  return 0;
}

int plugin_user_zombie (plugin_user_t * user)
{
  user_t *u;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  user->flags |= PLUGIN_FLAG_ZOMBIE;
  u->flags |= PROTO_FLAG_ZOMBIE;

  return 0;
}

int plugin_user_unzombie (plugin_user_t * user)
{
  user_t *u;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  user->flags &= ~PLUGIN_FLAG_ZOMBIE;
  u->flags &= ~PROTO_FLAG_ZOMBIE;

  return 0;
}

int plugin_unban (unsigned char *nick)
{
  if (!nick)
    return 0;

  return banlist_del_bynick (&softbanlist, nick);
}

int plugin_ban_ip (plugin_user_t * op, unsigned long ip, unsigned long netmask,
		   buffer_t * message, unsigned long period)
{
  return banlist_add (&softbanlist, (op ? op->nick : HubSec->nick), "", ip, netmask, message,
		      period ? now.tv_sec + period : 0) != NULL;
}

int plugin_unban_ip (unsigned long ip, unsigned long netmask)
{
  return banlist_del_byip (&softbanlist, ip, netmask);
}

int plugin_ban_nick (plugin_user_t * op, unsigned char *nick, buffer_t * message,
		     unsigned long period)
{
  return banlist_add (&softbanlist, (op ? op->nick : HubSec->nick), nick, 0L, 0L, message,
		      period ? now.tv_sec + period : 0) != NULL;
}

int plugin_ban (plugin_user_t * op, unsigned char *nick, unsigned long ip,
		unsigned long netmask, buffer_t * message, unsigned long period)
{
  return banlist_add (&softbanlist, (op ? op->nick : HubSec->nick), nick, ip, netmask, message,
		      period ? now.tv_sec + period : 0) != NULL;
}

int plugin_unban_nick (unsigned char *nick)
{
  return banlist_del_bynick (&softbanlist, nick);
}

int plugin_unban_ip_hard (unsigned long ip, unsigned long netmask)
{
  return banlist_del_byip (&hardbanlist, ip, netmask);
}

int plugin_ban_ip_hard (plugin_user_t * op, unsigned long ip, unsigned long netmask,
			buffer_t * message, unsigned long period)
{
  return banlist_add (&hardbanlist, (op ? op->nick : HubSec->nick), "", ip, netmask, message,
		      period ? now.tv_sec + period : 0) != NULL;
}

int plugin_user_banip_hard (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
			    unsigned long period)
{
  user_t *u;
  buffer_t *b;
  unsigned int retval;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  banlist_add (&hardbanlist, (op ? op->nick : HubSec->nick), u->nick, u->ipaddress, 0xffffffff,
	       message, period ? now.tv_sec + period : 0);

  b = bf_alloc (265 + bf_used (message));

  bf_printf (b, _("You have been banned by %s because: %.*s\n"), (op ? op->nick : HubSec->nick),
	     bf_used (message), message->s);

  plugin_send_event (((plugin_private_t *) user->private), PLUGIN_EVENT_BAN, b);

  retval =
    ((plugin_private_t *) user->private)->proto->user_forcemove (u, config.KickBanRedirect, b);

  bf_free (b);

  return retval;
}

int plugin_user_bannick (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
			 unsigned long period)
{
  user_t *u;
  buffer_t *b;
  unsigned int retval;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  banlist_add (&softbanlist, (op ? op->nick : HubSec->nick), u->nick, 0L, 0L, message,
	       period ? now.tv_sec + period : 0);

  b = bf_alloc (265 + bf_used (message));

  bf_printf (b, _("You have been banned by %s because: %.*s\n"), (op ? op->nick : HubSec->nick),
	     bf_used (message), message->s);

  plugin_send_event (((plugin_private_t *) user->private), PLUGIN_EVENT_BAN, b);

  retval =
    ((plugin_private_t *) user->private)->proto->user_forcemove (u, config.KickBanRedirect, b);

  bf_free (b);

  return retval;
}

int plugin_user_ban (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
		     unsigned long period)
{
  user_t *u;
  buffer_t *b;
  unsigned int retval;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  banlist_add (&softbanlist, (op ? op->nick : HubSec->nick), u->nick, u->ipaddress, 0xffffffff,
	       message, period ? now.tv_sec + period : 0);

  b = bf_alloc (265 + bf_used (message));

  bf_printf (b, _("You have been banned by %s because: %.*s\n"), (op ? op->nick : HubSec->nick),
	     bf_used (message), message->s);
  retval =
    ((plugin_private_t *) user->private)->proto->user_forcemove (u, config.KickBanRedirect, b);

  bf_free (b);

  return retval;
}

int plugin_user_findnickban (buffer_t * buf, unsigned char *nick)
{
  banlist_entry_t *ne;
  struct in_addr ipa, netmask;

  ne = banlist_find_bynick (&softbanlist, nick);
  if (!ne)
    return 0;

  ipa.s_addr = ne->ip;
  netmask.s_addr = ne->netmask;

  if (ne->expire) {
    if (ne->ip) {
      return bf_printf (buf, _("Found nick ban by %s for %s (IP %s) for %lus because: %.*s"),
			ne->op, ne->nick, print_ip (ipa, netmask), ne->expire - now.tv_sec,
			bf_used (ne->message), ne->message->s);
    } else {
      return bf_printf (buf, _("Found nick ban by %s for %s for %lus because: %.*s"), ne->op,
			ne->nick, ne->expire - now.tv_sec, bf_used (ne->message), ne->message->s);
    }
  } else {
    if (ne->ip) {
      return bf_printf (buf, _("Found permanent nick ban by %s for %s (IP %s) because: %.*s"),
			ne->op, ne->nick, print_ip (ipa, netmask), bf_used (ne->message),
			ne->message->s);
    } else {
      return bf_printf (buf, _("Found permanent nick ban by %s for %s because: %.*s"), ne->op,
			ne->nick, bf_used (ne->message), ne->message->s);
    }
  }
}

int plugin_user_findipban (buffer_t * buf, unsigned long ip)
{
  struct in_addr ipa, netmask;
  banlist_entry_t *ie;

  ie = banlist_find_byip (&softbanlist, ip);
  if (!ie)
    return 0;

  ipa.s_addr = ie->ip;
  netmask.s_addr = ie->netmask;
  if (ie->expire) {
    if (ie->nick[0]) {
      return bf_printf (buf, _("Found IP ban by %s for %s (%s) for %lus because: %.*s"), ie->op,
			print_ip (ipa, netmask), ie->nick, ie->expire - now.tv_sec,
			bf_used (ie->message), ie->message->s);
    } else {
      return bf_printf (buf, _("Found IP ban by %s for %s for %lus because: %.*s"), ie->op,
			print_ip (ipa, netmask), ie->expire - now.tv_sec, bf_used (ie->message),
			ie->message->s);
    }
  } else {
    if (ie->nick[0]) {
      return bf_printf (buf, _("Found permanent ban by %s for %s (%s) because: %.*s"), ie->op,
			print_ip (ipa, netmask), ie->nick, bf_used (ie->message), ie->message->s);
    } else {
      return bf_printf (buf, _("Found permanent ban by %s for %s because: %.*s"), ie->op,
			print_ip (ipa, netmask), bf_used (ie->message), ie->message->s);
    }
  }
}

int plugin_user_findiphardban (buffer_t * buf, unsigned long ip)
{
  struct in_addr ipa, netmask;
  banlist_entry_t *ie;

  ie = banlist_find_byip (&hardbanlist, ip);
  if (!ie)
    return 0;

  ipa.s_addr = ie->ip;
  netmask.s_addr = ie->netmask;
  if (ie->expire) {
    if (ie->nick[0]) {
      return bf_printf (buf, _("Found IP ban by %s for %s (%s) for %lus because: %.*s"), ie->op,
			print_ip (ipa, netmask), ie->nick, ie->expire - now.tv_sec,
			bf_used (ie->message), ie->message->s);
    } else {
      return bf_printf (buf, _("Found IP ban by %s for %s for %lus because: %.*s"), ie->op,
			print_ip (ipa, netmask), ie->expire - now.tv_sec, bf_used (ie->message),
			ie->message->s);
    }
  } else {
    if (ie->nick[0]) {
      return bf_printf (buf, _("Found permanent ban by %s for %s (%s) because: %.*s"), ie->op,
			print_ip (ipa, netmask), ie->nick, bf_used (ie->message), ie->message->s);
    } else {
      return bf_printf (buf, _("Found permanent ban by %s for %s because: %.*s"), ie->op,
			print_ip (ipa, netmask), bf_used (ie->message), ie->message->s);
    }
  }
}

int plugin_banlist (buffer_t * output)
{
  unsigned long bucket, n;
  banlist_entry_t *lst, *e;
  struct in_addr ip, nm;

  n = 0;
  dlhashlist_foreach (&softbanlist.list_ip, bucket) {
    lst = dllist_bucket (&softbanlist.list_ip, bucket);
    dllist_foreach (lst, e) {
      ip.s_addr = e->ip;
      nm.s_addr = e->netmask;
      if (e->expire) {
	bf_printf (output, _("%s %s by %s Expires: %s Message: %.*s\n"), e->nick, print_ip (ip, nm),
		   e->op, time_print (e->expire - now.tv_sec), bf_used (e->message), e->message->s);
      } else {
	bf_printf (output, _("%s %s by %s Message: %.*s\n"), e->nick, print_ip (ip, nm), e->op,
		   bf_used (e->message), e->message->s);
      }
      n++;
    }
  }
  return (n > 0);
}

int plugin_hardbanlist (buffer_t * output)
{
  unsigned long bucket, n;
  banlist_entry_t *lst, *e;
  struct in_addr ip, nm;

  n = 0;
  dlhashlist_foreach (&hardbanlist.list_ip, bucket) {
    lst = dllist_bucket (&hardbanlist.list_ip, bucket);
    dllist_foreach (lst, e) {
      ip.s_addr = e->ip;
      nm.s_addr = e->netmask;
      if (e->expire) {
	bf_printf (output, _("%s %s by %s Expires: %s Message: %.*s\n"), e->nick, print_ip (ip, nm),
		   e->op, time_print (e->expire - now.tv_sec), bf_used (e->message), e->message->s);
      } else {
	bf_printf (output, _("%s %s by %s Message: %.*s\n"), e->nick, print_ip (ip, nm), e->op,
		   bf_used (e->message), e->message->s);
      }
      n++;
    }
  }
  return (n > 0);
}

int plugin_user_setrights (plugin_user_t * user, unsigned long long cap, unsigned long long ncap)
{
  user_t *u;

  u = ((plugin_private_t *) user->private)->parent;

  user->rights |= cap;
  user->rights &= ~ncap;

  u->rights |= cap;
  u->rights &= ~ncap;

  return 0;
}

unsigned long long plugin_right_create (unsigned char *name, unsigned char *help)
{
  flag_t *f = cap_custom_add (name, help);

  return f ? f->flag : 0LL;
}

int plugin_right_destroy (unsigned char *name)
{
  return cap_custom_remove (name);
}

/******************************* UTILITIES: USER MANAGEMENT **************************************/

int plugin_user_redirect (plugin_user_t * user, buffer_t * message)
{
  user_t *u;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  return ((plugin_private_t *) user->private)->proto->user_redirect (u, message);
}

int plugin_user_forcemove (plugin_user_t * user, unsigned char *destination, buffer_t * message)
{
  user_t *u;

  if (!user)
    return 0;

  u = ((plugin_private_t *) user->private)->parent;

  if (u->state == PROTO_STATE_VIRTUAL)
    return 0;

  if (!destination || !*destination)
    return ((plugin_private_t *) user->private)->proto->user_redirect (u, message);

  return ((plugin_private_t *) user->private)->proto->user_forcemove (u, destination, message);
}

/******************************* UTILITIES: USER MANAGEMENT **************************************/

int plugin_user_say (plugin_user_t * src, buffer_t * message)
{
  user_t *u;

  if (src) {
    u = ((plugin_private_t *) src->private)->parent;
  } else {
    u = HubSec;
  }

  /* delete trailing \n */
  if (bf_used (message) && (message->s[bf_used (message) - 1] == '\n')) {
    message->s[bf_used (message) - 1] = '\0';
    message->e--;
  }
  return ((plugin_private_t *) u->plugin_priv)->proto->chat_main (u, message);
}

int plugin_user_raw (plugin_user_t * tgt, buffer_t * message)
{
  user_t *u;

  if (!tgt)
    return 0;

  u = ((plugin_private_t *) tgt->private)->parent;

  /* delete trailing \n */
  if (bf_used (message) && (message->s[bf_used (message) - 1] == '\n')) {
    message->s[bf_used (message) - 1] = '\0';
    message->e--;
  }

  return ((plugin_private_t *) u->plugin_priv)->proto->raw_send (u, message);
}


int plugin_user_raw_all (buffer_t * message)
{
  /* delete trailing \n */
  if (bf_used (message) && (message->s[bf_used (message) - 1] == '\n')) {
    message->s[bf_used (message) - 1] = '\0';
    message->e--;
  }

  return ((plugin_private_t *) HubSec->plugin_priv)->proto->raw_send_all (message);
}

int plugin_user_sayto (plugin_user_t * src, plugin_user_t * target, buffer_t * message, int direct)
{
  buffer_t *b;
  user_t *u, *t;

  if (src) {
    u = ((plugin_private_t *) src->private)->parent;
  } else {
    u = HubSec;
  }

  /* delete trailing \n */
  b = message;
  while (b->next)
    b = b->next;
  if (bf_used (b) && (b->s[bf_used (b) - 1] == '\n')) {
    b->s[bf_used (b) - 1] = '\0';
    b->e--;
  }

  t = ((plugin_private_t *) target->private)->parent;

  if (t->state == PROTO_STATE_VIRTUAL)
    return 0;

  return direct ? ((plugin_private_t *) u->plugin_priv)->proto->chat_send_direct (u, t, message) :
    ((plugin_private_t *) u->plugin_priv)->proto->chat_send (u, t, message);
}

int plugin_user_priv (plugin_user_t * src, plugin_user_t * target, plugin_user_t * user,
		      buffer_t * message, int direct)
{
  buffer_t *b;
  user_t *u, *t, *s;

  if (src) {
    u = ((plugin_private_t *) src->private)->parent;
  } else {
    u = HubSec;
  }

  /* delete trailing \n */
  b = message;
  while (b->next)
    b = b->next;
  if (bf_used (b) && (b->s[bf_used (b) - 1] == '\n')) {
    b->s[bf_used (b) - 1] = '\0';
    b->e--;
  }

  t = ((plugin_private_t *) target->private)->parent;

  if (user) {
    s = ((plugin_private_t *) user->private)->parent;
  } else {
    s = HubSec;
  }

  return direct ? ((plugin_private_t *) target->private)->proto->chat_priv_direct (u, t, s, message)
    : ((plugin_private_t *) target->private)->proto->chat_priv (u, t, s, message);
}

int plugin_user_printf (plugin_user_t * user, const char *format, ...)
{
  va_list ap;
  buffer_t *buf;

  buf = bf_alloc (1024);

  va_start (ap, format);
  bf_vprintf (buf, format, ap);
  va_end (ap);

  plugin_user_sayto (NULL, user, buf, 0);

  bf_free (buf);

  return 0;
}

/******************************* ROBOTS EVENTS *******************************************/
/* FIXME */
extern proto_t nmdc_proto;
plugin_user_t *plugin_robot_add (unsigned char *name, unsigned char *description,
				 plugin_event_handler_t * handler)
{
  user_t *u;
  plugin_private_t *priv;

  u = nmdc_proto.robot_add (name, description);
  u->rights |= CAP_KEY;
  plugin_new_user ((void *) &u->plugin_priv, u, &nmdc_proto);

  priv = ((plugin_private_t *) u->plugin_priv);
  priv->handler = handler;

  return &priv->user;
}



int plugin_robot_remove (plugin_user_t * robot)
{
  user_t *u;

  u = ((plugin_private_t *) robot->private)->parent;

  /* does the plugin_del_user */
  ((plugin_private_t *) robot->private)->proto->robot_del (u);

  return 0;
}

plugin_event_handler_t *plugin_robot_set_handler (plugin_user_t * robot,
						  plugin_event_handler_t * handler)
{
  user_t *u;
  plugin_private_t *priv;
  plugin_event_handler_t *old;

  u = ((plugin_private_t *) robot->private)->parent;
  priv = ((plugin_private_t *) u->plugin_priv);
  old = priv->handler;
  priv->handler = handler;

  return old;
}

/******************************* REQUEST EVENTS *******************************************/

int plugin_parse (plugin_user_t * user, buffer_t * buf)
{
  user_t *u;

  u = ((plugin_private_t *) user->private)->parent;

  ((plugin_private_t *) user->private)->proto->handle_token (u, buf);
  return 0;
}

/******************************* REQUEST EVENTS *******************************************/

int plugin_request (plugin_t * plugin, unsigned long event, plugin_event_handler_t * handler)
{
  plugin_event_request_t *request;

  if (event > PLUGIN_EVENT_NUMBER)
    return -1;

  request = malloc (sizeof (plugin_event_request_t));
  memset (request, 0, sizeof (plugin_event_request_t));
  request->plugin = plugin;
  request->handler = handler;

  /* link it in the list */
  request->next = manager->eventhandles[event].next;
  request->next->prev = request;
  request->prev = &manager->eventhandles[event];
  manager->eventhandles[event].next = request;

  if (plugin)
    plugin->events++;

  return 0;
}

int plugin_ignore (plugin_t * plugin, unsigned long event, plugin_event_handler_t * handler)
{
  plugin_event_request_t *request;

  for (request = manager->eventhandles[event].next; request != &manager->eventhandles[event];
       request = request->next)
    if ((request->plugin == plugin) && (request->handler == handler))
      break;

  if (!request)
    return 0;

  request->next->prev = request->prev;
  request->prev->next = request->next;

  free (request);
  if (plugin)
    plugin->events--;

  return 0;
}

/******************************* CLAIM/RELEASE *******************************************/

int plugin_claim (plugin_t * plugin, plugin_user_t * user, void *cntxt)
{
  plugin_private_t *priv = user->private;

  ASSERT (!priv->store[plugin->id]);
  priv->store[plugin->id] = cntxt;

  plugin->privates++;

  return 0;
}

int plugin_release (plugin_t * plugin, plugin_user_t * user)
{
  plugin_private_t *priv = user->private;

  priv->store[plugin->id] = NULL;

  plugin->privates--;

  return 0;
}

void *plugin_retrieve (plugin_t * plugin, plugin_user_t * user)
{
  plugin_private_t *priv = user->private;

  return priv->store[plugin->id];
}



/******************************* REGISTER/UNREGISTER *******************************************/

plugin_t *plugin_register (const char *name)
{
  plugin_t *plugin;

  plugin = malloc (sizeof (plugin_t));
  if (!plugin)
    return NULL;

  memset (plugin, 0, sizeof (plugin_t));
  strncpy ((char *) plugin->name, name, PLUGIN_NAME_LENGTH);
  ((char *) plugin->name)[PLUGIN_NAME_LENGTH - 1] = 0;

  plugin->id = pluginIDs++;

  /* link into dllink list */
  plugin->next = manager->plugins.next;
  plugin->prev = &manager->plugins;
  plugin->next->prev = plugin;
  manager->plugins.next = plugin;

  return plugin;
}

int plugin_unregister (plugin_t * plugin)
{
  plugin_private_t *p;

  /* force clearing of all private data */
  for (p = manager->privates.next; p != &manager->privates; p = p->next)
    if (p->store[plugin->id]) {
      free (p->store[plugin->id]);
      p->store[plugin->id] = NULL;
      plugin->privates--;
    }

  /* verify everything is clean. */
  ASSERT (!plugin->privates);
  ASSERT (!plugin->events);
  ASSERT (!plugin->robots);

  /* unlink and free */
  plugin->next->prev = plugin->prev;
  plugin->prev->next = plugin->next;
  free (plugin);

  return 0;
}

/******************************* ENTRYPOINT *******************************************/

unsigned long plugin_user_event (plugin_user_t * user, unsigned long event, void *token)
{
  return plugin_send_event (user ? ((plugin_private_t *) user->private) : NULL, event, token);
}

unsigned long plugin_send_event (plugin_private_t * priv, unsigned long event, void *token)
{
  unsigned long retval = PLUGIN_RETVAL_CONTINUE;
  plugin_event_request_t *r, *e;

  e = &manager->eventhandles[event];
  r = manager->eventhandles[event].next;
  if (priv) {
    if (priv->handler)
      retval = priv->handler (&priv->user, NULL, event, token);

    if (retval)
      return retval;

    for (; r != e; r = r->next) {
      retval = r->handler (&priv->user, priv->store[r->plugin->id], event, token);
      if (retval)
	break;
    }
  } else {
    for (; r != e; r = r->next) {
      retval = r->handler (NULL, NULL, event, token);
      if (retval)
	break;
    }
  }

  return retval;
}

/****************************** CORE USERMANAGEMENT ******************************************/

unsigned long plugin_update_user (user_t * u)
{
  if ((((plugin_private_t *) u->plugin_priv)->user.share == u->share) &&
      (((plugin_private_t *) u->plugin_priv)->user.active == u->active) &&
      (((plugin_private_t *) u->plugin_priv)->user.slots == u->slots) &&
      (((plugin_private_t *) u->plugin_priv)->user.hubs[0] == u->hubs[0]) &&
      (((plugin_private_t *) u->plugin_priv)->user.hubs[1] == u->hubs[1]) &&
      (((plugin_private_t *) u->plugin_priv)->user.hubs[2] == u->hubs[2]) &&
      (((plugin_private_t *) u->plugin_priv)->user.ipaddress == u->ipaddress) &&
      (((plugin_private_t *) u->plugin_priv)->user.op == u->op) &&
      (((plugin_private_t *) u->plugin_priv)->user.flags == u->flags) &&
      (((plugin_private_t *) u->plugin_priv)->user.supports == u->supports) &&
      (((plugin_private_t *) u->plugin_priv)->user.rights == u->rights))
    return 0;

  ((plugin_private_t *) u->plugin_priv)->user.share = u->share;
  ((plugin_private_t *) u->plugin_priv)->user.active = u->active;
  ((plugin_private_t *) u->plugin_priv)->user.slots = u->slots;
  ((plugin_private_t *) u->plugin_priv)->user.hubs[0] = u->hubs[0];
  ((plugin_private_t *) u->plugin_priv)->user.hubs[1] = u->hubs[1];
  ((plugin_private_t *) u->plugin_priv)->user.hubs[2] = u->hubs[2];
  ((plugin_private_t *) u->plugin_priv)->user.ipaddress = u->ipaddress;
  ((plugin_private_t *) u->plugin_priv)->user.op = u->op;
  ((plugin_private_t *) u->plugin_priv)->user.flags = u->flags;
  ((plugin_private_t *) u->plugin_priv)->user.rights = u->rights;
  ((plugin_private_t *) u->plugin_priv)->user.supports = u->supports;

  return plugin_send_event (((plugin_private_t *) u->plugin_priv), PLUGIN_EVENT_UPDATE, NULL);
}


unsigned long plugin_new_user (plugin_private_t ** priv, user_t * u, proto_t * p)
{

  ASSERT (!*priv);

  *priv = malloc (sizeof (plugin_private_t) + (sizeof (void *) * manager->num));
  memset (*priv, 0, sizeof (plugin_private_t));

  strncpy (((plugin_private_t *) u->plugin_priv)->user.nick, u->nick, NICKLENGTH);
  strncpy (((plugin_private_t *) u->plugin_priv)->user.client, u->client, 64);
  strncpy (((plugin_private_t *) u->plugin_priv)->user.versionstring, u->versionstring, 64);
  ((plugin_private_t *) u->plugin_priv)->user.version = u->version;

  (*priv)->parent = u;
  (*priv)->proto = p;
  (*priv)->user.private = *priv;
  (*priv)->store = (void *) (((char *) *priv) + sizeof (plugin_private_t));

  return plugin_update_user (u);
}


unsigned long plugin_del_user (plugin_private_t ** priv)
{
  ASSERT (*priv);
  free (*priv);
  *priv = NULL;

  return 0;
}


/******************************* INIT *******************************************/

int plugin_config_xml (xml_node_t * node)
{
  int retval = 0;

  /* add configvalues */
  retval = cap_save (node);
  retval = config_save (node);
  retval = accounts_save (node);
  retval = banlist_save (&hardbanlist, xml_node_add (node, "HardBanList"));
  retval = banlist_save (&softbanlist, xml_node_add (node, "SoftBanList"));

  plugin_send_event (NULL, PLUGIN_EVENT_SAVE, node);

  return retval;
}

int plugin_config_save (buffer_t * output)
{
  FILE *fp;
  int retval = 0;
  xml_node_t *node;

  /* write to file */
  fp = fopen (HUBSOFT_NAME ".xml", "w+");
  if (!fp) {
    bf_printf (output, _("Error saving configuration to %s: %s\n"), HUBSOFT_NAME ".xml",
	       strerror (errno));
    goto leave;
  }

  /* start tree */
  node = xml_node_add (NULL, HUBSOFT_NAME);

  retval = plugin_config_xml (node);

  xml_write (fp, node);
  fclose (fp);

  /* clear tree */
  xml_free (node);

leave:
  return 0;

}

int plugin_config_load (buffer_t * output)
{
  int retval = 0;
  FILE *fp;
  xml_node_t *node, *list;

  fp = fopen (HUBSOFT_NAME ".xml", "r+");
  if (!fp) {
    if (output)
      bf_printf (output, _("Error loading configuration from %s: %s\n"), HUBSOFT_NAME ".xml",
		 strerror (errno));
    goto leave;
  }

  node = xml_read (fp);

  fclose (fp);

  if (!node)
    goto leave;

  if (strcmp (node->name, HUBSOFT_NAME)) {
    xml_free (node);
    goto leave;
  }

  cap_load (node);
  config_load (node);
  accounts_load (node);
  list = xml_node_find (node, "HardBanList");
  banlist_load (&hardbanlist, list);
  list = xml_node_find (node, "SoftBanList");
  banlist_load (&softbanlist, list);

  plugin_send_event (NULL, PLUGIN_EVENT_LOAD, node);

  xml_free (node);

  return 0;
leave:

  config_load_old (ConfigFile);
  accounts_load_old (AccountsFile);
  banlist_load_old (&hardbanlist, HardBanFile);
  banlist_load_old (&softbanlist, SoftBanFile);

  plugin_send_event (NULL, PLUGIN_EVENT_LOAD, NULL);

  return retval;
}

/******************************* INIT *******************************************/

int plugin_init ()
{
  int i;

  pluginIDs = 0;

  manager = malloc (sizeof (plugin_manager_t));
  memset (manager, 0, sizeof (plugin_manager_t));

  /* init dl lists */
  manager->plugins.next = &manager->plugins;
  manager->plugins.prev = &manager->plugins;
  manager->privates.next = &manager->privates;
  manager->privates.prev = &manager->privates;
  for (i = 0; i < PLUGIN_EVENT_NUMBER; i++) {
    manager->eventhandles[i].next = &manager->eventhandles[i];
    manager->eventhandles[i].prev = &manager->eventhandles[i];
  }
  manager->num = PLUGIN_MAX_PLUGINS;

  ConfigFile = strdup (DEFAULT_SAVEFILE);
  HardBanFile = strdup (DEFAULT_HARDBANFILE);
  SoftBanFile = strdup (DEFAULT_SOFTBANFILE);
  AccountsFile = strdup (DEFAULT_ACCOUNTSFILE);

  return 0;
}
