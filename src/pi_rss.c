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

#include "esocket.h"
#include "etimer.h"

#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "hash.h"
#include "xml.h"
#include "utils.h"

#include "aqtime.h"
#include "buffer.h"
#include "commands.h"
#include "plugin.h"

#include "../config.h"

#ifndef __USE_W32_SOCKETS
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#ifdef USE_WINDOWS
#  include "sys_windows.h"
#endif

#define PI_RSS_CONNECT_TIMEOUT	3000
#define PI_RSS_INPUT_BUFFERSIZE 20480

#define PI_RSS_ERROR_RETRY 30

#define PI_RSS_STATE_UPDATE	1
#define PI_RSS_STATE_EVAL	2

typedef struct rss_element {
  struct rss_element *next, *prev;

  buffer_t *entry;
  unsigned long hash;
  unsigned long stamp;
} rss_element_t;

typedef struct rss_feed {
  struct rss_feed *next, *prev;

  unsigned char *name;

  /* timing information */
  unsigned char *lastmodified;
  unsigned long stamp;
  unsigned long interval;

  /* feed data */
  unsigned char *title;
  unsigned char *description;
  rss_element_t includes;
  rss_element_t elems;

  /* location */
  unsigned char *address;
  unsigned int port;
  unsigned char *path;

  /* targeting */
  unsigned char *user;
  unsigned long long rights;

  /* used during retrieval */
  esocket_t *es;
  etimer_t timer;
  buffer_t *recvd;

  /* state information: what to do after retrieval */
  unsigned int state;
  plugin_user_t *target;
} rss_feed_t;

esocket_handler_t *pi_rss_handler = NULL;
unsigned int pi_rss_es_type;
unsigned long rss_deadline;
unsigned long maxitemlength;
unsigned long maxentryage;
unsigned long rss_silent;

plugin_t *pi_rss;

rss_feed_t feedlist;

int pi_rss_handle_timeout (rss_feed_t * feed);

unsigned char *rss_html_filter (unsigned char *s)
{
  int intag = 0;
  unsigned char *d, *c;

  d = malloc (strlen (s) * 6 + 1);
  if (!d)
    return NULL;

  for (c = d; *s; s++) {
    switch (*s) {
      case '<':
	intag = 1;
	break;
      case '>':
	intag = 0;
	break;
      case '|':
	if (!intag) {
	  memcpy (c, "&#134;", 6);
	  c += 6;
	}
	break;
      default:
	if (!intag)
	  *c++ = *s;
    }
  }
  *c = 0;

  /* shorten string */
  c = d;
  d = strdup (c);
  free (c);

  return d;
}

buffer_t *rss_item_printf (rss_feed_t * feed, xml_node_t * elem)
{
  rss_element_t *item;
  xml_node_t *node;
  buffer_t *buf;
  unsigned char *clean;

  buf = bf_alloc (1024);
  if (!buf)
    return NULL;

  if (feed->includes.next != &feed->includes) {
    for (item = feed->includes.next; item != &feed->includes; item = item->next) {
      node = xml_node_find (elem, item->entry->s);
      if (!node)
	continue;
      if (!node->value)
	continue;
      clean = rss_html_filter (node->value);
      if (strlen (clean) > maxitemlength) {
	buf = bf_printf_resize (buf, "%.*s...\n", maxitemlength, clean);
      } else {
	buf = bf_printf_resize (buf, "%.*s\n", maxitemlength, clean);
      }
      free (clean);
    }
  } else {
    for (node = elem->children; node; node = xml_next (node)) {
      if (!node->value)
	continue;
      clean = rss_html_filter (node->value);
      if (strlen (clean) > maxitemlength) {
	buf = bf_printf_resize (buf, "%.*s...\n", maxitemlength, clean);
      } else {
	buf = bf_printf_resize (buf, "%.*s\n", maxitemlength, clean);
      }
      free (clean);
    };
  }

  return buf;
}

buffer_t *rss_item_atom_printf (rss_feed_t * feed, xml_node_t * elem)
{
  rss_element_t *item;
  xml_attr_t *attr;
  xml_node_t *node;
  buffer_t *buf;
  unsigned char *clean;

  buf = bf_alloc (1024);
  if (!buf)
    return NULL;

  if (feed->includes.next != &feed->includes) {
    for (item = feed->includes.next; item != &feed->includes; item = item->next) {
      node = xml_node_find (elem, item->entry->s);
      if (!node)
	continue;
      if (!strcmp (node->name, "link")) {
	attr = xml_attr_find (node, "href");
	clean = rss_html_filter (attr->value);
	if (strlen (clean) > maxitemlength) {
	  buf = bf_printf_resize (buf, "%.*s...\n", maxitemlength, clean);
	} else {
	  buf = bf_printf_resize (buf, "%.*s\n", maxitemlength, clean);
	}
	free (clean);
      } else {
	if (!node->value)
	  continue;
	clean = rss_html_filter (node->value);
	if (strlen (clean) > maxitemlength) {
	  buf = bf_printf_resize (buf, "%.*s...\n", maxitemlength, clean);
	} else {
	  buf = bf_printf_resize (buf, "%.*s\n", maxitemlength, clean);
	}
	free (clean);
      }
    }
  } else {
    for (node = elem->children; node; node = xml_next (node)) {
      if (!strcmp (node->name, "link")) {
	attr = xml_attr_find (node, "href");
	clean = rss_html_filter (attr->value);
	if (strlen (clean) > maxitemlength) {
	  buf = bf_printf_resize (buf, "%.*s...\n", maxitemlength, clean);
	} else {
	  buf = bf_printf_resize (buf, "%.*s\n", maxitemlength, clean);
	}
	free (clean);
      } else {
	if (!node->value)
	  continue;
	clean = rss_html_filter (node->value);
	if (strlen (clean) > maxitemlength) {
	  buf = bf_printf_resize (buf, "%.*s...\n", maxitemlength, clean);
	} else {
	  buf = bf_printf_resize (buf, "%.*s\n", maxitemlength, clean);
	}
	free (clean);
      };
    };
  }

  return buf;
}

rss_element_t *rss_elem_find (rss_element_t * list, unsigned long hash)
{
  rss_element_t *elem;

  for (elem = list->next; elem != list; elem = elem->next)
    if (elem->hash == hash)
      return elem;

  return NULL;
}

void rss_elem_del (rss_element_t * elem)
{
  elem->next->prev = elem->prev;
  elem->prev->next = elem->next;
  bf_free (elem->entry);
  free (elem);
}

rss_element_t *rss_item_add (rss_feed_t * feed, xml_node_t * node)
{
  unsigned long hash;
  buffer_t *buf;
  rss_element_t *elem;

  buf = rss_item_printf (feed, node);
  hash = SuperFastHash (buf->s, bf_used (buf));

  if (rss_elem_find (&feed->elems, hash))
    goto error;

  elem = malloc (sizeof (rss_element_t));
  if (!elem)
    goto error;

  elem->hash = hash;
  elem->entry = buf;
  elem->stamp = now.tv_sec;

  elem->next = &feed->elems;
  elem->prev = feed->elems.prev;
  elem->next->prev = elem;
  elem->prev->next = elem;

  return elem;

error:
  bf_free (buf);
  return NULL;
}

rss_element_t *rss_item_atom_add (rss_feed_t * feed, xml_node_t * node)
{
  unsigned long hash;
  buffer_t *buf;
  rss_element_t *elem;

  buf = rss_item_atom_printf (feed, node);
  hash = SuperFastHash (buf->s, bf_used (buf));

  if (rss_elem_find (&feed->elems, hash))
    goto error;

  elem = malloc (sizeof (rss_element_t));
  if (!elem)
    goto error;

  elem->hash = hash;
  elem->entry = buf;
  elem->stamp = now.tv_sec;

  elem->next = &feed->elems;
  elem->prev = feed->elems.prev;
  elem->next->prev = elem;
  elem->prev->next = elem;

  return elem;

error:
  bf_free (buf);
  return NULL;
}


unsigned int rss_item_timeout (rss_feed_t * feed, unsigned long timeout)
{
  unsigned long cutoff = now.tv_sec - timeout;
  rss_element_t *elem, *prev;

  prev = &feed->elems;
  elem = feed->elems.next;

  for (; elem != &feed->elems; prev = elem, elem = elem->next) {
    if (elem->stamp >= cutoff)
      continue;

    elem->next->prev = elem->prev;
    elem->prev->next = elem->next;

    bf_free (elem->entry);
    free (elem);

    elem = prev->next;
  }
  return 0;
}

unsigned int rss_item_list (rss_feed_t * feed, buffer_t * output, unsigned long stamp)
{
  unsigned int count = 0;
  rss_element_t *elem;

  for (elem = feed->elems.prev; (elem->stamp > stamp) && (elem != &feed->elems);
       elem = elem->prev, count++)
    output = bf_printf_resize (output, "%.*s\n", bf_used (elem->entry), elem->entry->s);

  return count;
}

rss_element_t *rss_include_add (rss_feed_t * feed, unsigned char *include)
{
  rss_element_t *elem;
  unsigned long l = strlen (include);
  unsigned long hash = SuperFastHash (include, l);

  if (rss_elem_find (&feed->includes, hash))
    return NULL;

  elem = malloc (sizeof (rss_element_t));
  if (!elem)
    return NULL;

  elem->hash = hash;
  elem->entry = bf_alloc (l + 1);
  if (!elem->entry) {
    free (elem);
    return NULL;
  }
  bf_strcat (elem->entry, include);
  elem->stamp = now.tv_sec;

  elem->next = &feed->includes;
  elem->prev = feed->includes.prev;
  elem->next->prev = elem;
  elem->prev->next = elem;

  return elem;
}

rss_feed_t *rss_feed_add (unsigned char *name, unsigned char *url)
{
  unsigned char *p;
  rss_feed_t *feed;

  feed = malloc (sizeof (rss_feed_t));
  if (!feed)
    return NULL;
  memset (feed, 0, sizeof (rss_feed_t));

  etimer_init (&feed->timer, (etimer_handler_t *) pi_rss_handle_timeout, feed);

  feed->elems.next = &feed->elems;
  feed->elems.prev = &feed->elems;
  feed->includes.next = &feed->includes;
  feed->includes.prev = &feed->includes;
  feed->stamp = 0;

  feed->name = strdup (name);

  if (url) {
    if (!strncmp (url, "http://", 7))
      url += 7;

    feed->address = strdup (url);
    feed->path = strchr (feed->address, '/');
    if (feed->path) {
      *feed->path = 0;
      feed->path++;
      if (!*feed->path)
	feed->path = NULL;
    }

    p = strchr (feed->address, ':');
    if (p) {
      *p++ = 0;
      feed->port = atoi (p);
    }
  }
  if (!feed->port)
    feed->port = 80;

  feed->next = &feedlist;
  feed->prev = feedlist.prev;
  feed->next->prev = feed;
  feed->prev->next = feed;

  return feed;
}

void rss_feed_del (rss_feed_t * feed)
{
  feed->prev->next = feed->next;
  feed->next->prev = feed->prev;

  while (feed->includes.next != &feed->includes)
    rss_elem_del (feed->includes.next);
  while (feed->elems.next != &feed->elems)
    rss_elem_del (feed->elems.next);

  free (feed->name);
  free (feed->address);
  free (feed);
}

rss_feed_t *rss_feed_find (unsigned char *name)
{
  rss_feed_t *feed;

  for (feed = feedlist.next; feed != &feedlist; feed = feed->next) {
    if (!strcmp (feed->name, name))
      return feed;
  }
  return NULL;
}

int rss_feed_parse (rss_feed_t * feed, buffer_t * b)
{
  xml_node_t *base, *node;

  base = xml_import (b);
  if (!base)
    return -1;

  /* for spec info see http://diveintomark.org/archives/2004/02/04/incompatible-rss */
  if (!strcmp (base->name, "rss")) {
    /* this is an rss based dist, 
     *  version 0.91 (Netscape, July 1999)
     *  version 0.91 (Userland, July 2000)
     *          uses textInput iso testinpunt
     *          uses 1-24 for hour, not 0-23.
     *  version 0.92 (Userland, December 2000)
     *          uses 1-24 for hour, not 0-23.
     *  version 0.93 (Userland, April 2001)
     *          uses 1-24 for hour, not 0-23.
     *  version 0.94 (Userland, August 2002)
     *          uses 1-24 for hour, not 0-23.
     *  version 2.0  (Userland, September 2002)
     *          uses 1-24 for hour, not 0-23.
     *  version 2.01 (Userland, November 2002)
     *  item are part of the rss element.
     *    contain title, link, description
     */
    node = xml_node_find (base, "channel");
    xml_child_get (node, "title", XML_TYPE_STRING, &feed->title);
    xml_child_get (node, "description", XML_TYPE_STRING, &feed->description);

    node = xml_node_find (node, "item");
    do {
      rss_item_add (feed, node);
      node = xml_node_find_next (node, "item");
    } while (node);
  } else if (!strcmp (base->name, "rdf:RDF")) {
    /* this is RDF syntax based. 
     *   version 0.90 (Netscape, March 1999)
     *   version 1.0  (RSS-DEV Working Group, December 2000)
     *  channel contains feed information, no items.
     *  item are part of the rdf:RDF element.
     *    contain title, link, description
     */
    node = xml_node_find (base, "channel");
    xml_child_get (node, "title", XML_TYPE_STRING, &feed->title);
    xml_child_get (node, "description", XML_TYPE_STRING, &feed->description);
    node = xml_node_find (base, "item");
    do {
      rss_item_add (feed, node);
      node = xml_node_find_next (node, "item");
    } while (node);
  } else if (!strcmp (base->name, "feed")) {
    /*
     * Atom based feed!
     *
     *  item are called "entry" and part of the feed element
     *  FIXME link is not accessible. stored in an attribute!
     *    contain title, link, summary and/or content
     */
    xml_child_get (base, "title", XML_TYPE_STRING, &feed->title);

    node = xml_node_find (base, "entry");
    do {
      rss_item_atom_add (feed, node);
      node = xml_node_find_next (node, "entry");
    } while (node);
  } else {
    /* unknown format */
    xml_free (base);
    return -1;
  }

  //rss_item_timeout (&feed->elems, now.tv_sec - maxentryage)

  if (feed->target)
    plugin_user_sayto (NULL, feed->target, bf_buffer ("Feed updated."), 0);

  xml_free (base);

  return 0;
}

int rss_feed_describe (rss_feed_t * feed, plugin_user_t * target, buffer_t * b)
{
  xml_node_t *base, *node, *elem;
  buffer_t *output, *msg;

  base = xml_import (b);
  if (!base)
    return -1;

  output = bf_alloc (1024);
  if (!output) {
    xml_free (base);
    return -1;
  }
  msg = output;

  bf_printf (output, "Feed information %s\n", feed->name);

  /* for spec info see http://diveintomark.org/archives/2004/02/04/incompatible-rss */
  if (!strcmp (base->name, "rss")) {
    /* this is an rss based dist, 
     *  version 0.91 (Netscape, July 1999)
     *  version 0.91 (Userland, July 2000)
     *          uses textInput iso testinpunt
     *          uses 1-24 for hour, not 0-23.
     *  version 0.92 (Userland, December 2000)
     *          uses 1-24 for hour, not 0-23.
     *  version 0.93 (Userland, April 2001)
     *          uses 1-24 for hour, not 0-23.
     *  version 0.94 (Userland, August 2002)
     *          uses 1-24 for hour, not 0-23.
     *  version 2.0  (Userland, September 2002)
     *          uses 1-24 for hour, not 0-23.
     *  version 2.01 (Userland, November 2002)
     *  item are part of the rss element.
     *    contain title, link, description
     */
    node = xml_node_find (base, "channel");
    elem = xml_node_find (node, "title");
    output = bf_printf_resize (output, _(" Title: %s\n"), elem->value);
    feed->title = strdup (elem->value);
    elem = xml_node_find (node, "link");
    output = bf_printf_resize (output, _(" Link: %s\n"), elem->value);
    elem = xml_node_find (node, "description");
    output = bf_printf_resize (output, _(" Description: %s\n"), elem->value);

    /* print a sample entry */
    output = bf_printf_resize (output, _("\n Example node:\n"));
    node = xml_node_find (node, "item");
    if (node->children) {
      for (elem = node->children; elem; elem = xml_next (elem)) {
	if (!elem->value)
	  continue;
	output = bf_printf_resize (output, "%s: %s\n", elem->name, elem->value);
      }
    }

    /* do the actual parsing */
    do {
      rss_item_add (feed, node);
      node = xml_node_find_next (node, "item");
    } while (node);

  } else if (!strcmp (base->name, "rdf:RDF")) {
    /* this is RDF syntax based. 
     *   version 0.90 (Netscape, March 1999)
     *   version 1.0  (RSS-DEV Working Group, December 2000)
     *  channel contains feed information, no items.
     *  item are part of the rdf:RDF element.
     *    contain title, link, description
     */
    node = xml_node_find (base, "channel");
    elem = xml_node_find (node, "title");
    output = bf_printf_resize (output, _(" Title: %s\n"), elem->value);
    feed->title = strdup (elem->value);
    elem = xml_node_find (node, "link");
    output = bf_printf_resize (output, _(" Link: %s\n"), elem->value);
    elem = xml_node_find (node, "description");
    output = bf_printf_resize (output, _(" Description: %s\n"), elem->value);

    /* print a sample entry */
    output = bf_printf_resize (output, _("\n Example node:\n"));
    node = xml_node_find (base, "item");
    if (node->children) {
      for (elem = node->children; elem; elem = xml_next (elem)) {
	if (!elem->value)
	  continue;
	output = bf_printf_resize (output, "%s: %s\n", elem->name, elem->value);
      }
    }
    /* do the actual parsing */
    do {
      rss_item_add (feed, node);
      node = xml_node_find_next (node, "item");
    } while (node);
  } else if (!strcmp (base->name, "feed")) {
    xml_attr_t *attr;

    /*
     * Atom based feed!
     *
     *  item are called "entry" and part of the feed element
     *  FIXME link is not accessible. stored in an attribute!
     *    contain title, link, summary and/or content
     */
    elem = xml_node_find (base, "title");
    output = bf_printf_resize (output, _(" Title: %s\n"), elem->value);
    feed->title = strdup (elem->value);
    elem = xml_node_find (base, "link");
    attr = xml_attr_find (elem, "href");
    if (attr)
      output = bf_printf_resize (output, _(" Link: %s\n"), attr->value);

    /* print a sample entry */
    output = bf_printf_resize (output, _("\n Example node:\n"));
    node = xml_node_find (base, "entry");
    if (node->children) {
      for (elem = node->children; elem; elem = xml_next (elem)) {
	if (!elem->value) {
	  if (!strcmp (elem->name, "link")) {
	    attr = xml_attr_find (elem, "href");
	    if (attr)
	      output = bf_printf_resize (output, "%s: %s\n", elem->name, attr->value);
	  }
	  continue;
	}
	output = bf_printf_resize (output, "%s: %s\n", elem->name, elem->value);
      }
    }
    /* do the actual parsing */
    do {
      rss_item_atom_add (feed, node);
      node = xml_node_find_next (node, "entry");
    } while (node);
  } else {
    /* unknown format */
    output = bf_printf_resize (output, _("Unknown format.\n"));
  }

  //rss_item_timeout (&feed->elems, now.tv_sec - maxentryage)

  if (target)
    plugin_user_sayto (NULL, target, msg, 0);

  bf_free (output);
  xml_free (base);

  return 0;
}

/******************************************************************************/

int pi_rss_report (rss_feed_t * feed, unsigned long stamp)
{
  plugin_user_t *tgt, *prev;
  buffer_t *output = bf_alloc (1024);

  if (!output)
    return 0;

  bf_printf (output, "\n%s", feed->title);
  if (feed->description)
    bf_printf (output, " - %s", feed->description);
  /* add a extra space to it so the hub doesn't delete the last line. */
  bf_printf (output, "\n \n");

  if (rss_item_list (feed, output, stamp)) {
    if (feed->user) {
      /* send to specific user */
      if ((tgt = plugin_user_find (feed->user)))
	plugin_user_priv (NULL, tgt, NULL, output, 0);
    } else if (feed->rights) {
      /* send to all users with certain rights */
      tgt = prev = NULL;
      while (plugin_user_next (&tgt)) {
	prev = tgt;
	if ((tgt->rights & feed->rights) != feed->rights)
	  continue;
	if (plugin_user_priv (NULL, tgt, NULL, output, 0) < 0)
	  tgt = prev;
      }
    } else {
      /* just send to main chat */
      plugin_user_say (NULL, output);
    }
  }

  bf_free (output);

  return 0;
}

int pi_rss_finish (rss_feed_t * feed)
{
  unsigned int code;
  unsigned char *c, *e;
  buffer_t *buf;
  unsigned long stamp;

  /* close the socket */
  esocket_close (feed->es);
  esocket_remove_socket (feed->es);
  feed->es = NULL;
  etimer_cancel (&feed->timer);
  stamp = feed->stamp;
  feed->stamp = now.tv_sec;

  /* if this is the first finish, don't print everything. */
  if (!stamp)
    stamp = now.tv_sec;

  /* update the deadline if necessary */
  if (rss_deadline > (feed->stamp + feed->interval))
    rss_deadline = feed->stamp + feed->interval;

  /* we need the whole document in 1 block, \0 terminted */
  buf = bf_copy (feed->recvd, 1);
  *buf->e++ = '\0';
  bf_free (feed->recvd);
  feed->recvd = NULL;

  /* first we process the response line. */
  c = buf->s;
  /* skip HTTP/1.x */
  c = strchr (c, ' ');
  if (!c)
    goto leave;
  c++;
  code = atoi (c);
  switch (code) {
      /* success */
    case 200:
      break;

      /* moved permanently */
    case 301:
      c = strstr (c, "Location: ");
      if (!c)
	goto leave;
      c += 10;
      e = strstr (c, "\r\n");
      *e = 0;
      DPRINTF ("RSS: Feed %s got 301 Moved Permanently: %s\n", feed->name, c);

      errno = 0;
      plugin_perror (_("RSS fetch failed, destination moved permanently: %s"), c);
      goto leave;

      /* not changed */
    case 304:
      DPRINTF ("RSS: Feed %s got 304 Not Changed\n", feed->name);
      goto leave;

      /* error */
    default:
      e = strstr (c, "\r\n");
      *e = 0;
      errno = 0;
      if (!rss_silent)
	plugin_perror (_("RSS fetch failed: %s"), c);

      goto leave;
  }

  /* we try to find a Last-Modified header */
  c = strstr (buf->s, "Last-Modified:");
  if (c) {
    /* copy the header out */
    c = strchr (c, ' ');
    e = strstr (c, "\r\n");
    *e = 0;
    if (feed->lastmodified)
      free (feed->lastmodified);
    feed->lastmodified = strdup (c);
    *e = '\r';
  };

  /* we skip all http headers */
  c = strstr (buf->s, "\r\n\r\n");
  if (!c) {
    bf_free (buf);
    return -1;
  }
  buf->s = c + 4;

  DPRINTF ("RSS: Succesfully updated %s\n", feed->name);

  /* parse result */
  errno = 0;
  switch (feed->state) {
    case PI_RSS_STATE_UPDATE:
      if (rss_feed_parse (feed, buf) < 0)
	plugin_perror (_("RSS: %s is not a valid RSS feed.\n"), feed->name);
      if (!feed->target)
	pi_rss_report (feed, stamp);
      break;
    case PI_RSS_STATE_EVAL:
      if (rss_feed_describe (feed, feed->target, buf) < 0)
	plugin_perror (_("RSS: %s is not a valid RSS feed.\n"), feed->name);
      break;
  }

leave:
  bf_free (buf);

  return 0;
}

int pi_rss_retrieve (rss_feed_t * feed, buffer_t * output)
{
  int result;

  /* not yet initialized */
  if (pi_rss_es_type == UINT_MAX)
    return -1;

  /* busy */
  if (feed->es) {
    if (output)
      bf_printf (output, "Busy.");
    return -1;
  }

  /* open socket */
  feed->recvd = NULL;
  feed->es =
    esocket_new (pi_rss_handler, pi_rss_es_type, AF_INET, SOCK_STREAM, 0, (uintptr_t) feed);
  if (!feed->es) {
    if (output)
      bf_printf (output, _("Unable to create socket.\n"));
    return -1;
  }

  /* connect */
  if ((result = esocket_connect (feed->es, feed->address, feed->port)) != 0) {
    if (result > 0) {
      if (output)
	bf_printf (output, _("RSS update ERROR: %s: connect: %s\n"), feed->address,
		   gai_strerror (result));
      DPRINTF ("pi_rss: connect: %s", gai_strerror (result));
    } else {
      if (output)
	bf_printf (output, _("RSS update ERROR: %s: connect: %s\n"), feed->address,
		   strerror (-result));
      DPRINTF ("pi_rss: connect: %s", strerror (-result));
    }
    esocket_close (feed->es);
    esocket_remove_socket (feed->es);
    feed->es = NULL;

    /* retry for error. */
    feed->stamp = now.tv_sec - feed->interval + PI_RSS_ERROR_RETRY;

    /* update the deadline if necessary */
    if (rss_deadline > (feed->stamp + feed->interval))
      rss_deadline = feed->stamp + feed->interval;

    return -1;
  }

  /* set timeout */
  etimer_init (&feed->timer, (etimer_handler_t *) pi_rss_handle_timeout, feed);
  etimer_set (&feed->timer, PI_RSS_CONNECT_TIMEOUT);

  DPRINTF ("RSS: started update of %s http://%s:%d/%s\n", feed->name, feed->address, feed->port,
	   feed->path);

  return 0;
}

int pi_rss_handle_input (esocket_t * s)
{
  int n;
  buffer_t *buf;
  rss_feed_t *feed = (rss_feed_t *) s->context;

  /* read data */
  do {
    buf = bf_alloc (PI_RSS_INPUT_BUFFERSIZE);
    if (!buf)
      return -1;
    n = esocket_recv (s, buf);
    if (n < 0) {
      bf_free (buf);

      if (errno != EAGAIN) {
	if (!rss_silent)
	  plugin_perror (_("RSS read (%s)"), feed->name);
	esocket_close (feed->es);
	esocket_remove_socket (feed->es);
	feed->es = NULL;
	etimer_cancel (&feed->timer);

	/* retry for error. */
	feed->stamp = now.tv_sec - feed->interval + PI_RSS_ERROR_RETRY;

	/* update the deadline if necessary */
	if (rss_deadline > (feed->stamp + feed->interval))
	  rss_deadline = feed->stamp + feed->interval;
	return -1;
      }

      return 0;
    }
    /* connection closed, transfer succesful */
    if (n == 0)
      goto succes;

    bf_append (&feed->recvd, buf);
  } while (n > 0);

  /* set timeout */
  etimer_set (&feed->timer, PI_RSS_CONNECT_TIMEOUT);

  return 0;
succes:
  bf_free (buf);
  return pi_rss_finish (feed);
}

int pi_rss_handle_output (esocket_t * s)
{
  buffer_t *buf;
  rss_feed_t *feed = (rss_feed_t *) s->context;

  buf = bf_alloc (256 + (feed->path ? strlen (feed->path) : 0));
  if (!buf)
    goto leave;

  /* create request:
   *  GET request for the feed url.
   *  Host is included to support multihosting
   *  User-Agent: just to brag :P
   *  if available a "If-Modified-Since:" is used.
   */
  bf_printf (buf, "GET /%s HTTP/1.0\r\n"
	     "Host: %s\r\n"
	     "User-Agent: %s/%s\r\n", feed->path ? feed->path : (unsigned char *) "", feed->address,
	     HUBSOFT_NAME, VERSION);
  if (feed->lastmodified)
    bf_printf (buf, "If-Modified-Since: %s\r\n", feed->lastmodified);
  bf_printf (buf, "\r\n");

  if (esocket_send (feed->es, buf, 0) < 0)
    goto leave;

  bf_free (buf);

  etimer_set (&feed->timer, PI_RSS_CONNECT_TIMEOUT);

  return 0;
leave:
  /* error handling */
  if (buf)
    bf_free (buf);

  if (!rss_silent)
    plugin_perror (_("RSS output (%s)"), feed->name);

  esocket_close (feed->es);
  esocket_remove_socket (feed->es);
  feed->es = NULL;
  etimer_cancel (&feed->timer);

  /* retry for error. */
  feed->stamp = now.tv_sec - feed->interval + PI_RSS_ERROR_RETRY;

  /* update the deadline if necessary */
  if (rss_deadline > (feed->stamp + feed->interval))
    rss_deadline = feed->stamp + feed->interval;

  return -1;
}

int pi_rss_handle_error (esocket_t * s)
{
  rss_feed_t *feed = (rss_feed_t *) s->context;

  if (s->state == SOCKSTATE_FREED)
    return 0;

  if (!rss_silent)
    plugin_perror (_("RSS error (%s)"), feed->name);
  esocket_close (feed->es);
  esocket_remove_socket (feed->es);
  feed->es = NULL;
  etimer_cancel (&feed->timer);

  /* retry for error. */
  feed->stamp = now.tv_sec - feed->interval + PI_RSS_ERROR_RETRY;

  return 0;
};

int pi_rss_handle_timeout (rss_feed_t * feed)
{
  if (feed->es->state == SOCKSTATE_FREED)
    return 0;

  if (feed->es->state == SOCKSTATE_RESOLVING) {
    etimer_set (&feed->timer, PI_RSS_CONNECT_TIMEOUT);
    return 0;
  }

  if (!rss_silent)
    plugin_perror (_("RSS timeout (%s)"), feed->name);
  esocket_close (feed->es);
  esocket_remove_socket (feed->es);
  feed->es = NULL;

  /* retry for error. */
  feed->stamp = now.tv_sec - feed->interval + PI_RSS_ERROR_RETRY;

  return 0;
};

unsigned long pi_rss_handler_rss (plugin_user_t * user, buffer_t * output, void *dummy,
				  unsigned int argc, unsigned char **argv)
{
  rss_feed_t *feed = NULL;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <feed>\n"), argv[0]);
    bf_printf (output, _(" Available feeds:\n"));
    for (feed = feedlist.next; feed != &feedlist; feed = feed->next) {
      bf_printf (output, "   %s (", feed->name);
      if (feed->description) {
	bf_printf (output, "%s - %s", feed->title,
		   feed->description ? feed->description : (unsigned char *) _("No description."));
      } else {
	bf_printf (output, "%s", feed->title);
      }
      bf_printf (output, ")\n");
    }
    return 0;
  }

  feed = rss_feed_find (argv[1]);
  if (!feed) {
    bf_printf (output, _("Feed %s not found\n"), argv[1]);
    return -1;
  }

  bf_printf (output, "%s", feed->title);
  if (feed->description)
    bf_printf (output, " - %s", feed->description);
  bf_printf (output, "\n");

  rss_item_list (feed, output, 0);

  return 0;
}

unsigned long pi_rss_handler_rssadd (plugin_user_t * user, buffer_t * output, void *dummy,
				     unsigned int argc, unsigned char **argv)
{
  unsigned long interval;
  rss_feed_t *feed;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <name> <interval> <url>\n"), argv[0]);
    return 0;
  }

  /* first check interval spec */
  interval = time_parse (argv[2]);
  if (!interval) {
    bf_printf (output, _("Feed interval invalid: %s\n"), argv[2]);
    return 0;
  }

  feed = rss_feed_find (argv[1]);
  if (feed) {
    bf_printf (output, _("Feed %s already exists.\n"), argv[1]);
    return 0;
  }

  /* create feed */
  feed = rss_feed_add (argv[1], argv[3]);
  if (!feed) {
    bf_printf (output, _("Feed creation failed.\n"), argv[1]);
    return -1;
  }

  /* do initial eval */
  feed->interval = interval;
  feed->state = PI_RSS_STATE_EVAL;
  feed->target = user;

  pi_rss_retrieve (feed, output);

  return 0;
}

unsigned long pi_rss_handler_rssselect (plugin_user_t * user, buffer_t * output, void *dummy,
					unsigned int argc, unsigned char **argv)
{
  char *e, *t;
  rss_feed_t *feed;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <name> <fields>\n"), argv[0]);
    return 0;
  }

  feed = rss_feed_find (argv[1]);
  if (!feed) {
    bf_printf (output, _("Feed %s not found\n"), argv[1]);
    return -1;
  }

  bf_printf (output, "\n");
  e = strdup (argv[2]);
  t = strtok (e, ", ");
  while (t) {
    bf_printf (output, _(" Adding %s\n"), t);
    rss_include_add (feed, t);
    t = strtok (NULL, ", ");
  }
  free (e);

  if (feed->es) {
    bf_printf (output, _(" Feed is active and will be updated later.\n"));
    return -1;
  }

  bf_printf (output, _(" Updating feed now...\n"));
  feed->state = PI_RSS_STATE_UPDATE;
  feed->target = user;

  /* clear the element list to prevent double entries. */
  while (feed->elems.next != &feed->elems)
    rss_elem_del (feed->elems.next);

  /* clear lastmodified so a new copy is retrieved and all
   * entries get updated correctly 
   */
  if (feed->lastmodified) {
    free (feed->lastmodified);
    feed->lastmodified = NULL;
  }

  pi_rss_retrieve (feed, output);

  return 0;
}

unsigned long pi_rss_handler_rsslist (plugin_user_t * user, buffer_t * output, void *dummy,
				      unsigned int argc, unsigned char **argv)
{
  rss_feed_t *feed;
  rss_element_t *elem;

  if (feedlist.next == &feedlist) {
    bf_printf (output, _("No feeds configured\n"));
  } else {
    /* show all included tags for all feeds. */
    for (feed = feedlist.next; feed != &feedlist; feed = feed->next) {
      bf_printf (output, _("Feed: %s (Updated %s)\n"), feed->name, time_print (feed->interval));
      if (feed->description) {
	bf_printf (output, "  %s - %s\n", feed->title,
		   feed->description ? feed->description : (unsigned char *) _("No description."));
      } else {
	bf_printf (output, "  %s\n", feed->title);
      }
      if (feed->user) {
	bf_printf (output, _("  Target user: %s\n"), feed->user);
      } else if (feed->rights) {
	bf_printf (output, _("  Target rights: "));
	flags_print (Capabilities + CAP_PRINT_OFFSET, output, feed->rights);
	bf_printf (output, "\n");
      }
      if (feed->port != 80) {
	bf_printf (output, _("  Link: http://%s:%u/%s\n"), feed->address, feed->port, feed->path);
      } else {
	bf_printf (output, _("  Link: http://%s/%s\n"), feed->address, feed->path);
      }
      if (feed->lastmodified)
	bf_printf (output, _("  Last modified: %s\n"), feed->lastmodified);
      if (feed->es) {
	bf_printf (output, _("  Next update: Running...\n"));
      } else {
	bf_printf (output, _("  Next update: %s\n"),
		   time_print (feed->stamp + feed->interval - now.tv_sec));
      }
      if (feed->includes.next != &feed->includes) {
	bf_printf (output, _(" Includes: "));
	for (elem = feed->includes.next; elem != &feed->includes; elem = elem->next) {
	  bf_printf (output, "  %.*s", bf_used (elem->entry), elem->entry->s);
	}
	bf_printf (output, "\n");
      }
    }
  }

  return 0;
}

unsigned long pi_rss_handler_rssdel (plugin_user_t * user, buffer_t * output, void *dummy,
				     unsigned int argc, unsigned char **argv)
{
  rss_feed_t *feed;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <feed>\n"), argv[0]);
    return 0;
  }

  feed = rss_feed_find (argv[1]);
  if (!feed)
    return 0;

  if (feed->es) {
    bf_printf (output, _("Feed is being updated. please retry in a few moments.\n"));
    return 0;
  }
  rss_feed_del (feed);

  bf_printf (output, _("Feed %s deleted\n"), argv[1]);

  return 0;
}


unsigned long pi_rss_handler_rsstarget (plugin_user_t * user, buffer_t * output, void *dummy,
					unsigned int argc, unsigned char **argv)
{
  rss_feed_t *feed;
  unsigned long long ncap = 0;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <feed> user <target> &#124; rights <rights> &#124; main\n"
			 "  user <target>: send feed output to user\n"
			 "  right <rights>: send feed output to all user with <rights>\n"),
	       argv[0]);
    return 0;
  }

  feed = rss_feed_find (argv[1]);
  if (!feed)
    return 0;

  if (feed->user)
    free (feed->user);
  if (!strcmp (argv[2], "user")) {
    feed->user = strdup (argv[3]);
    feed->rights = 0;
    bf_printf (output, _("Sending output from feed %s to %s\n"), feed->name, feed->user);
  } else if (!strcmp (argv[2], "rights")) {
    feed->user = NULL;
    flags_parse (Capabilities, output, argc, argv, 3, &feed->rights, &ncap);
    bf_printf (output, _("Sending output from feed %s to all users with rights "), feed->name);
    flags_print (Capabilities + CAP_PRINT_OFFSET, output, feed->rights);
    bf_printf (output, "\n");
  } else if (!strcmp (argv[2], "main")) {
    feed->user = NULL;
    feed->rights = 0;
  } else {
    return pi_rss_handler_rsstarget (user, output, dummy, 1, argv);
  }

  return 0;
}

unsigned long pi_rss_handler_rssforce (plugin_user_t * user, buffer_t * output, void *dummy,
				       unsigned int argc, unsigned char **argv)
{
  rss_feed_t *feed;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <feed>\n"), argv[0]);
    return 0;
  }

  feed = rss_feed_find (argv[1]);
  if (!feed)
    return 0;

  if (feed->es) {
    bf_printf (output, _("Feed is being updated. please retry in a few moments.\n"));
    return 0;
  }
  pi_rss_retrieve (feed, output);

  bf_printf (output, _("Feed %s update started.\n"), argv[1]);

  return 0;
}


unsigned long pi_rss_handle_save (plugin_user_t * user, void *ctxt, unsigned long event,
				  void *token)
{
  rss_feed_t *feed;
  rss_element_t *elem;
  xml_node_t *node = (xml_node_t *) token;

  if (!node)
    return 0;

  node = xml_node_add (node, "RSS");

  /* show all included tags for all feeds. */
  for (feed = feedlist.next; feed != &feedlist; feed = feed->next) {
    node = xml_node_add (node, "Feed");
    xml_node_add_value (node, "Name", XML_TYPE_STRING, feed->name);
    xml_node_add_value (node, "Address", XML_TYPE_STRING, feed->address);
    xml_node_add_value (node, "Port", XML_TYPE_UINT, &feed->port);
    xml_node_add_value (node, "Path", XML_TYPE_STRING, feed->path);
    xml_node_add_value (node, "User", XML_TYPE_STRING, feed->user);
    xml_node_add_value (node, "Rights", XML_TYPE_CAP, &feed->rights);
    xml_node_add_value (node, "Interval", XML_TYPE_LONG, &feed->interval);
    node = xml_node_add (node, "Includes");
    if (feed->includes.next != &feed->includes) {
      for (elem = feed->includes.next; elem != &feed->includes; elem = elem->next)
	xml_node_add_value (node, "Include", XML_TYPE_STRING, elem->entry->s);
    }
    node = xml_parent (node);
    node = xml_parent (node);
  }
  return 0;
}

unsigned long pi_rss_handle_load (plugin_user_t * user, void *ctxt, unsigned long event,
				  void *token)
{
  unsigned char *name = NULL, *address = NULL, *path = NULL, *usr = NULL;
  unsigned long long rights;
  unsigned int port;
  long interval;
  rss_feed_t *feed;
  xml_node_t *inc, *node = (xml_node_t *) token;

  if (!node)
    return 0;

  for (feed = feedlist.next; feed != &feedlist; feed = feedlist.next)
    rss_feed_del (feed);

  node = xml_node_find (node, "RSS");
  if (!node)
    return PLUGIN_RETVAL_CONTINUE;
  for (node = node->children; node; node = xml_next (node)) {
    if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
      continue;
    if (!xml_child_get (node, "Address", XML_TYPE_STRING, &address))
      continue;
    if (!xml_child_get (node, "Port", XML_TYPE_UINT, &port))
      continue;
    if (!xml_child_get (node, "Path", XML_TYPE_STRING, &path))
      continue;
    if (!xml_child_get (node, "User", XML_TYPE_STRING, &usr)) {
      if (usr)
	free (usr);
      usr = NULL;
    }
    if (!xml_child_get (node, "Rights", XML_TYPE_CAP, &rights)) {
      rights = 0;
    }
    if (!xml_child_get (node, "Interval", XML_TYPE_LONG, &interval))
      continue;

    feed = rss_feed_add (name, NULL);
    feed->address = strdup (address);
    feed->path = strdup (path);
    feed->port = port;
    feed->interval = interval;

    feed->rights = rights;
    if (usr && *usr)
      feed->user = strdup (usr);

    inc = xml_node_find (node, "Includes");
    for (inc = inc->children; inc; inc = xml_next (inc)) {
      if (!xml_node_get (inc, XML_TYPE_STRING, &name))
	continue;
      rss_include_add (feed, name);
    }

    feed->state = PI_RSS_STATE_UPDATE;
    feed->target = NULL;
    pi_rss_retrieve (feed, NULL);
  }

  if (name)
    free (name);
  if (address)
    free (address);
  if (path)
    free (path);
  if (usr)
    free (usr);

  return PLUGIN_RETVAL_CONTINUE;
}

unsigned long pi_rss_handle_update (plugin_user_t * user, void *ctxt, unsigned long event,
				    void *token)
{
  unsigned long t;
  rss_feed_t *feed;

  if (feedlist.next == &feedlist)
    return 0;

  if ((unsigned long) now.tv_sec < rss_deadline)
    return 0;

  /* run down all the feeds, start updates where necessary and determine
   * new rss_deadline
   */
  rss_deadline = LONG_MAX;
  for (feed = feedlist.next; feed != &feedlist; feed = feed->next) {
    /* feed is being updated. */
    if (feed->es)
      continue;

    t = feed->stamp + feed->interval;
    /* see if we need to start a feed update */
    if ((unsigned long) now.tv_sec > t) {
      feed->state = PI_RSS_STATE_UPDATE;
      feed->target = NULL;
      pi_rss_retrieve (feed, NULL);
      continue;
    }
    if (rss_deadline > t)
      rss_deadline = t;
  }

  /* if no new rss_deadline found, use 1m as default value. */
  if (rss_deadline == LONG_MAX)
    rss_deadline = now.tv_sec + 10;

  return 0;
}

int pi_rss_setup (esocket_handler_t * h)
{
  rss_feed_t *feed;

  pi_rss_handler = h;
  pi_rss_es_type =
    esocket_add_type (h, ESOCKET_EVENT_IN, pi_rss_handle_input, pi_rss_handle_output,
		      pi_rss_handle_error);

  plugin_request (NULL, PLUGIN_EVENT_CACHEFLUSH, (plugin_event_handler_t *) pi_rss_handle_update);

  /* kickstart feed update */
  for (feed = feedlist.next; feed != &feedlist; feed = feed->next) {
    feed->state = PI_RSS_STATE_UPDATE;
    feed->target = NULL;
    pi_rss_retrieve (feed, NULL);
  }

  rss_deadline = now.tv_sec + 60;

  return 0;
}

int pi_rss_init (esocket_handler_t * h)
{

  pi_rss = plugin_register ("rss");

  pi_rss_es_type = UINT_MAX;

  feedlist.next = &feedlist;
  feedlist.prev = &feedlist;

  rss_deadline = now.tv_sec + 60;

  plugin_request (NULL, PLUGIN_EVENT_LOAD, (plugin_event_handler_t *) pi_rss_handle_load);
  plugin_request (NULL, PLUGIN_EVENT_SAVE, (plugin_event_handler_t *) pi_rss_handle_save);

  maxitemlength = 256;
  maxentryage = 3600;
  rss_silent = 0;
  config_register ("rss.silent", CFG_ELEM_ULONG, &rss_silent,
		   _("If set, errors are not reported."));
  config_register ("rss.maxlength", CFG_ELEM_ULONG, &maxitemlength,
		   _("Maximum length of an RSS entry."));
  config_register ("rss.maxentryage", CFG_ELEM_ULONG, &maxentryage,
		   _("Maximum age of an RSS entry."));

  command_register ("rssadd", &pi_rss_handler_rssadd, CAP_CONFIG, _("Add a RSS or Atom feed."));
  command_register ("rsslist", &pi_rss_handler_rsslist, CAP_CONFIG,
		    _("List the RSS or Atom feeds."));
  command_register ("rssdel", &pi_rss_handler_rssdel, CAP_CONFIG, _("Delete a RSS or Atom feed."));
  command_register ("rssforce", &pi_rss_handler_rssforce, CAP_CONFIG,
		    _("Force an update on a RSS or Atom feed."));
  command_register ("rsstarget", &pi_rss_handler_rsstarget, CAP_CONFIG,
		    _("Configure where to send a RSS or Atom feed."));
  command_register ("rssselect", &pi_rss_handler_rssselect, CAP_CONFIG,
		    _("Select elements of a RSS or Atom feed."));
  command_register ("rss", &pi_rss_handler_rss, CAP_CHAT, _("Show an RSS or Atom feed."));

  return 0;
}
