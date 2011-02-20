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
#include <string.h>
#include <ctype.h>


#include "aqtime.h"
#include "defaults.h"
#include "banlist.h"
#include "buffer.h"
#include "hash.h"

#ifndef USE_WINDOWS
#  ifdef HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#  endif
#endif

__inline__ uint32_t netmask_to_numbits (uint32_t netmask)
{
  uint32_t nm, i;

  netmask = htonl (netmask);
  /* determine netmask */
  i = 32;
  nm = 0xffffffff;
  while (nm && (nm != netmask)) {
    nm = (nm << 1) & 0xfffffffe;
    --i;
  };

  return i;
}

__inline__ unsigned int nicktolower (unsigned char *dest, unsigned char *source)
{
  unsigned int l, n;

  for (l = 0; *source && (l < NICKLENGTH); l++)
    *dest++ = isalpha (*source) ? tolower (*source++) : *source++;

  n = l;
  while (n++ < NICKLENGTH)
    *dest++ = '\0';

  return l;
};

banlist_entry_t *banlist_add (banlist_t * list, unsigned char *op, unsigned char *nick, uint32_t ip,
			      uint32_t netmask, buffer_t * reason, unsigned long expire)
{
  banlist_entry_t *b;
  uint32_t i;
  unsigned char n[NICKLENGTH];
  unsigned int l;

  /* bad netmask */
  i = netmask_to_numbits (netmask);
  if (i > 32)
    return NULL;

  l = nicktolower (n, nick);

  /* delete any earlier bans of this ip. */
  if ((b = banlist_find_exact (list, nick, ip, netmask)))
    banlist_del (list, b);

  /* alloc and clear new element */
  b = malloc (sizeof (banlist_entry_t));

  /* init */
  dllist_init (&b->list_ip);
  dllist_init (&b->list_name);
  strncpy (b->nick, nick, NICKLENGTH);
  b->nick[NICKLENGTH - 1] = 0;
  strncpy (b->op, op, NICKLENGTH);
  b->op[NICKLENGTH - 1] = 0;
  b->ip = ip & netmask;
  b->netmask = netmask;
  b->message = bf_copy (reason, 1);
  *b->message->e = 0;
  b->expire = expire;

  /* mask netmask as used */
  list->netmask_inuse[i]++;

  /* put in hashlist */
  dlhashlist_prepend (&list->list_ip, one_at_a_time (ip & netmask) & BANLIST_HASHMASK,
		      (&b->list_ip));
  dlhashlist_prepend (&list->list_name, SuperFastHash (n, l) & BANLIST_NICK_HASHMASK,
		      (&b->list_name));

  return b;
}

unsigned int banlist_del (banlist_t * list, banlist_entry_t * e)
{
  if (!e)
    return 0;

  ASSERT (list->netmask_inuse[netmask_to_numbits (e->netmask)]);
  list->netmask_inuse[netmask_to_numbits (e->netmask)]--;

  dllist_del ((dllist_entry_t *) (&e->list_ip));
  dllist_del ((dllist_entry_t *) (&e->list_name));
  if (e->message)
    bf_free (e->message);

  free (e);

  return 1;
}

unsigned int banlist_del_byip (banlist_t * list, uint32_t ip, uint32_t netmask)
{
  banlist_entry_t *e;

  if (netmask != 0xffffffff) {
    e = banlist_find_bynet (list, ip, netmask);
  } else {
    e = banlist_find_byip (list, ip);
  }
  if (e)
    banlist_del (list, e);

  return (e != NULL);
}

unsigned int banlist_del_bynick (banlist_t * list, unsigned char *nick)
{
  banlist_entry_t *e;

  e = banlist_find_bynick (list, nick);
  if (e)
    banlist_del (list, e);

  return (e != NULL);
}


banlist_entry_t *banlist_find_bynet (banlist_t * list, uint32_t ip, uint32_t netmask)
{
  banlist_entry_t *e, *l;

repeat:
  l = dllist_bucket (&list->list_ip, one_at_a_time (ip & netmask) & BANLIST_HASHMASK);
  dllist_foreach (l, e)
    if ((e->ip == (ip & netmask)) && (e->netmask == netmask))
    break;

  if (e == dllist_end (l))
    return NULL;

  if (e->expire && (now.tv_sec > e->expire)) {
    banlist_del (list, e);
    e = NULL;
    goto repeat;
  }

  return e;
}

banlist_entry_t *banlist_find_exact (banlist_t * list, unsigned char *nick, uint32_t ip,
				     uint32_t netmask)
{
  banlist_entry_t *e, *l;
  unsigned char n[NICKLENGTH];
  unsigned int i;

  i = nicktolower (n, nick);

repeat:
  l = dllist_bucket (&list->list_ip, one_at_a_time (ip & netmask) & BANLIST_HASHMASK);
  dllist_foreach (l, e) {
    if ((e->ip == (ip & netmask)) && (e->netmask == netmask)
	&& (!strncasecmp (e->nick, nick, NICKLENGTH)))
      break;
  }

  if (e == dllist_end (l))
    return NULL;

  if (e->expire && (now.tv_sec > e->expire)) {
    banlist_del (list, e);
    e = NULL;
    goto repeat;
  }

  return e;
}

banlist_entry_t *banlist_find_byip (banlist_t * list, uint32_t ip)
{
  banlist_entry_t *e, *l;
  uint32_t netmask;
  long i;

repeat:
  e = NULL;
  l = NULL;
  netmask = 0xFFFFFFFF;
  for (i = 32; i >= 0; --i, netmask = (netmask << 1) & 0xFFFFFFFE) {
    if (!list->netmask_inuse[i])
      continue;
    l = dllist_bucket (&list->list_ip, one_at_a_time (ip & ntohl (netmask)) & BANLIST_HASHMASK);
    dllist_foreach (l, e)
      if (e->ip && (e->ip == (ip & e->netmask)))
      break;

    if (e != dllist_end (l))
      break;
  }

  if (e == dllist_end (l))
    return NULL;

  if (e->expire && (now.tv_sec > e->expire)) {
    banlist_del (list, e);
    e = NULL;
    goto repeat;
  }

  return e;
}

banlist_entry_t *banlist_find_bynick (banlist_t * list, unsigned char *nick)
{
  dllist_entry_t *p, *l;
  banlist_entry_t *e;
  unsigned char n[NICKLENGTH];
  unsigned int i;

  ASSERT (*nick);

  i = nicktolower (n, nick);
repeat:
  l = dllist_bucket (&list->list_name, SuperFastHash (n, i) & BANLIST_NICK_HASHMASK);
  dllist_foreach (l, p) {
    e = (banlist_entry_t *) ((char *) p - sizeof (dllist_t));
    if (!strncasecmp (e->nick, nick, NICKLENGTH))
      break;
  }
  if (p == dllist_end (l))
    return NULL;

  if (e && e->expire && (now.tv_sec > e->expire)) {
    banlist_del (list, e);
    e = NULL;
    goto repeat;
  }

  return e;
}

banlist_entry_t *banlist_find_bynick_next (banlist_t * list, banlist_entry_t * old,
					   unsigned char *nick)
{
  dllist_entry_t *p, *l;
  banlist_entry_t *e;
  unsigned char n[NICKLENGTH];
  unsigned int i;

  ASSERT (*nick);

repeat:
  i = nicktolower (n, nick);
  l = dllist_bucket (&list->list_name, SuperFastHash (n, i) & BANLIST_NICK_HASHMASK);
  dllist_foreach (l, p) {
    e = (banlist_entry_t *) ((char *) p - sizeof (dllist_t));
    if (old) {
      if (e != old)
	continue;
      old = NULL;
      continue;
    }
    if (!strncasecmp (e->nick, nick, NICKLENGTH))
      break;
  }
  if (p == dllist_end (l))
    return NULL;

  if (e->expire && (now.tv_sec > e->expire)) {
    banlist_del (list, e);
    e = NULL;
    goto repeat;
  }

  return e;
}

banlist_entry_t *banlist_find (banlist_t * list, unsigned char *nick, uint32_t ip)
{
  dllist_entry_t *p, *l;
  banlist_entry_t *e;
  unsigned char n[NICKLENGTH];
  unsigned int i;

  ASSERT (*nick);
  i = nicktolower (n, nick);

repeat:
  l = dllist_bucket (&list->list_name, SuperFastHash (n, i) & BANLIST_NICK_HASHMASK);
  dllist_foreach (l, p) {
    e = (banlist_entry_t *) ((char *) p - sizeof (dllist_t));
    if ((e->ip == (ip & e->netmask)) && !strncasecmp (e->nick, nick, NICKLENGTH))
      break;
  }
  if (p == dllist_end (l))
    return NULL;

  if (e->expire && (now.tv_sec > e->expire)) {
    banlist_del (list, e);
    e = NULL;
    goto repeat;
  }

  return e;
}

unsigned int banlist_cleanup (banlist_t * list)
{
  uint32_t i;
  banlist_entry_t *e;
  dllist_entry_t *l, *p, *n;

  dlhashlist_foreach (&list->list_name, i) {
    l = dllist_bucket (&list->list_name, i);
    for (p = l->next; p != dllist_end (l); p = n) {
      n = p->next;
      e = (banlist_entry_t *) ((char *) p - sizeof (dllist_t));
      if (e->expire && (e->expire > now.tv_sec))
	continue;

      ASSERT (list->netmask_inuse[netmask_to_numbits (e->netmask)]);
      list->netmask_inuse[netmask_to_numbits (e->netmask)]--;
      dllist_del ((dllist_entry_t *) & e->list_name);
      bf_free (e->message);
      free (e);
    }
  }
  return 0;
}

unsigned int banlist_save (banlist_t * list, xml_node_t * node)
{
  uint32_t i;
  banlist_entry_t *e;
  dllist_entry_t *l, *p, *n;

  node = xml_node_add (node, "BanList");
  dlhashlist_foreach (&list->list_ip, i) {
    l = dllist_bucket (&list->list_ip, i);
    for (p = l->next; p != dllist_end (l); p = n) {
      n = p->next;
      e = (banlist_entry_t *) p;
      if (e->expire && (e->expire < now.tv_sec)) {
	banlist_del (list, e);
	continue;
      }
      node = xml_node_add (node, "Ban");
      xml_node_add_value (node, "IP", XML_TYPE_IP, &e->ip);
      xml_node_add_value (node, "Netmask", XML_TYPE_IP, &e->netmask);
      xml_node_add_value (node, "Nick", XML_TYPE_STRING, &e->nick);
      xml_node_add_value (node, "OP", XML_TYPE_STRING, &e->op);
      xml_node_add_value (node, "Expire", XML_TYPE_ULONG, &e->expire);
      xml_node_add_value (node, "Message", XML_TYPE_STRING, e->message ? e->message->s : NULL);
      node = xml_parent (node);
    }
  }
  return 0;
}

unsigned int banlist_load (banlist_t * list, xml_node_t * node)
{
  unsigned long ip, netmask;
  long expire;
  unsigned char *nick = NULL, *op = NULL, *message = NULL;

  banlist_clear (list);

  node = xml_node_find (node, "BanList");
  if (!node)
    return 0;

  for (node = node->children; node; node = xml_next (node)) {
    if (!xml_child_get (node, "IP", XML_TYPE_IP, &ip))
      continue;
    if (!xml_child_get (node, "Netmask", XML_TYPE_IP, &netmask))
      continue;
    if (!xml_child_get (node, "Nick", XML_TYPE_STRING, &nick))
      continue;
    if (!xml_child_get (node, "OP", XML_TYPE_STRING, &op))
      continue;
    if (!xml_child_get (node, "Expire", XML_TYPE_LONG, &expire))
      continue;
    if (!xml_child_get (node, "Message", XML_TYPE_STRING, &message))
      continue;

    if (expire && (expire < now.tv_sec))
      continue;

    banlist_add (list, op, nick, ip, netmask, bf_buffer (message), expire);
  }
  if (nick)
    free (nick);
  if (op)
    free (op);
  if (message)
    free (message);

  return 0;
}

unsigned int banlist_load_old (banlist_t * list, unsigned char *file)
{
  FILE *fp;
  unsigned long l;
  banlist_entry_t e;

  banlist_clear (list);

  fp = fopen (file, "r+");
  if (!fp)
    return errno;
  fread (list->netmask_inuse, sizeof (unsigned long), 33, fp);
  memset (list->netmask_inuse, 0, sizeof (unsigned long) * 33);
  while (!feof (fp)) {
    if (!fread (&e.ip, sizeof (e.ip), 1, fp))
      break;
    fread (&e.netmask, sizeof (e.netmask), 1, fp);
    fread (e.nick, sizeof (e.nick), 1, fp);
    fread (e.op, sizeof (e.op), 1, fp);
    fread (&e.expire, sizeof (e.expire), 1, fp);
    fread (&l, sizeof (l), 1, fp);
    e.message = bf_alloc (l);
    fread (e.message->s, l, 1, fp);
    e.message->e += l;

    if (!e.expire || (e.expire > now.tv_sec))
      banlist_add (list, e.op, e.nick, e.ip, e.netmask, e.message, e.expire);

    bf_free (e.message);
  }
  fclose (fp);
  return 0;
}

void banlist_init (banlist_t * list)
{
  memset (list, 0, sizeof (banlist_t));
  dlhashlist_init ((dllist_t *) & list->list_ip, BANLIST_HASHSIZE);
  dlhashlist_init ((dllist_t *) & list->list_name, BANLIST_NICK_HASHSIZE);
}

void banlist_clear (banlist_t * list)
{
  uint32_t i;
  banlist_entry_t *e, *n, *lst;

  dlhashlist_foreach (&list->list_ip, i) {
    lst = dllist_bucket (&list->list_ip, i);
    for (e = (banlist_entry_t *) lst->list_ip.next; e != dllist_end (lst); e = n) {
      n = (banlist_entry_t *) e->list_ip.next;

      ASSERT (list->netmask_inuse[netmask_to_numbits (e->netmask)]);
      list->netmask_inuse[netmask_to_numbits (e->netmask)]--;
      dllist_del ((dllist_entry_t *) e);
      bf_free (e->message);
      free (e);
    }
  }
}
