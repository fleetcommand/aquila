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

#include "value.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include "hash.h"
#include "cap.h"
#include "utils.h"

#include "../config.h"

#ifndef __USE_W32_SOCKETS
#  include <sys/socket.h>
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#  ifdef HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#  endif
#endif /* __USE_W32_SOCKETS */

#ifdef USE_WINDOWS
#  include "sys_windows.h"
#endif


value_element_t *value_register (value_collection_t * collection, unsigned char *name,
				 value_type_t type, void *ptr, const unsigned char *help)
{
  int i;
  unsigned long hash;
  value_element_t *elem;

  elem = malloc (sizeof (value_element_t));
  if (!elem)
    return NULL;

  for (i = 0; name[i] && i < CONFIG_NAMELENGTH; i++)
    elem->name[i] = tolower (name[i]);
  if (i == CONFIG_NAMELENGTH)
    i--;
  elem->name[i] = '\0';
  elem->type = type;
  elem->val.v_ptr = ptr;
  elem->help = gettext (help);

  hash = SuperFastHash (elem->name, strlen (elem->name)) & CONFIG_HASHMASK;
  elem->next = collection->valuelist[hash].next;
  elem->next->prev = elem;
  elem->prev = &collection->valuelist[hash];
  collection->valuelist[hash].next = elem;

  {
    value_element_t *e;

    for (e = collection->value_sorted.onext; e != &collection->value_sorted; e = e->onext)
      if (strcmp (elem->name, e->name) < 0)
	break;
    e = e->oprev;

    elem->onext = e->onext;
    elem->onext->oprev = elem;
    elem->oprev = e;
    e->onext = elem;
  }

  return elem;
}

int value_unregister (value_collection_t * collection, unsigned char *name)
{
  unsigned int i;
  value_element_t *elem;
  unsigned long hash;
  unsigned char n[CONFIG_NAMELENGTH];

  for (i = 0; name[i] && i < CONFIG_NAMELENGTH; i++)
    n[i] = tolower (name[i]);
  if (i == CONFIG_NAMELENGTH)
    i--;
  n[i] = '\0';

  hash = SuperFastHash (n, strlen (n)) & CONFIG_HASHMASK;

  for (elem = collection->valuelist[hash].next; elem != &collection->valuelist[hash];
       elem = elem->next)
    if (!strcmp (n, elem->name))
      break;

  if (elem == &collection->valuelist[hash])
    return -1;

  elem->next->prev = elem->prev;
  elem->prev->next = elem->next;

  free (elem);

  return 0;
}

value_element_t *value_find (value_collection_t * collection, unsigned char *name)
{
  unsigned int i;
  value_element_t *elem;
  unsigned long hash;
  unsigned char n[CONFIG_NAMELENGTH];

  for (i = 0; name[i] && i < CONFIG_NAMELENGTH; i++)
    n[i] = tolower (name[i]);
  if (i == CONFIG_NAMELENGTH)
    i--;
  n[i] = '\0';

  hash = SuperFastHash (n, strlen (n)) & CONFIG_HASHMASK;

  for (elem = collection->valuelist[hash].next; elem != &collection->valuelist[hash];
       elem = elem->next)
    if (!strcmp (n, elem->name))
      return elem;

  return NULL;
}

void *value_retrieve (value_collection_t * collection, unsigned char *name)
{
  unsigned int i;
  value_element_t *elem;
  unsigned long hash;
  unsigned char n[CONFIG_NAMELENGTH];

  for (i = 0; name[i] && i < CONFIG_NAMELENGTH; i++)
    n[i] = tolower (name[i]);
  if (i == CONFIG_NAMELENGTH)
    i--;
  n[i] = '\0';

  hash = SuperFastHash (n, strlen (n)) & CONFIG_HASHMASK;

  for (elem = collection->valuelist[hash].next; elem != &collection->valuelist[hash];
       elem = elem->next)
    if (!strcmp (n, elem->name))
      return elem->val.v_ptr;

  return NULL;
}



int value_save (value_collection_t * collection, xml_node_t * base)
{
  xml_node_t *node;
  value_element_t *elem;

  node = xml_node_add (base, "Config");

  for (elem = collection->value_sorted.onext; elem != &collection->value_sorted; elem = elem->onext) {
    switch (elem->type) {
      case VAL_ELEM_STRING:
	xml_node_add_value (node, elem->name, elem->type, *elem->val.v_string);
	break;
      default:
	xml_node_add_value (node, elem->name, elem->type, elem->val.v_ptr);
    }
  }
  return 0;
}

int value_load (value_collection_t * collection, xml_node_t * node)
{
  value_element_t *elem;

  node = xml_node_find (node, "Config");
  if (!node)
    return 0;

  for (node = node->children; node; node = xml_next (node)) {
    elem = value_find (collection, node->name);
    if (!elem)
      continue;
    xml_node_get (node, elem->type, elem->val.v_ptr);
  }

  return 0;
}


int value_load_old (value_collection_t * collection, unsigned char *filename)
{
  unsigned int l;
  FILE *fp;
  value_element_t *elem;
  unsigned char *buffer, *c;

  fp = fopen (filename, "r");
  if (!fp)
    return errno;

  buffer = malloc (4096);
  while (!feof (fp)) {
    fgets (buffer, 4096, fp);
    for (c = buffer; *c && *c != ' '; c++);
    if (!*c)
      continue;
    *c++ = '\0';
    elem = value_find (collection, buffer);
    if (!elem)
      continue;
    switch (elem->type) {
      case VAL_ELEM_PTR:
	sscanf (c, "%p", elem->val.v_ptr);
	break;
      case VAL_ELEM_LONG:
	sscanf (c, "%ld", elem->val.v_long);
	break;
      case VAL_ELEM_ULONG:
      case VAL_ELEM_MEMSIZE:
	sscanf (c, "%lu", elem->val.v_ulong);
	break;
      case VAL_ELEM_CAP:
      case VAL_ELEM_BYTESIZE:
      case VAL_ELEM_ULONGLONG:
#ifndef USE_WINDOWS
	sscanf (c, "%Lu", elem->val.v_ulonglong);
#else
	sscanf (c, "%I64u", elem->val.v_ulonglong);
#endif
	break;
      case VAL_ELEM_INT:
	sscanf (c, "%d", elem->val.v_int);
	break;
      case VAL_ELEM_UINT:
	sscanf (c, "%u", elem->val.v_uint);
	break;
      case VAL_ELEM_DOUBLE:
	sscanf (c, "%lf", elem->val.v_double);
	break;
      case VAL_ELEM_STRING:
	if (*elem->val.v_string)
	  free (*elem->val.v_string);
	l = strlen (c);
	if (c[l - 1] == '\n')
	  c[l-- - 1] = '\0';
	if ((*c == '"') && (c[l - 1] == '"')) {
	  c[l - 1] = '\0';
	  c++;
	};
	*elem->val.v_string = string_unescape (c);
	break;
      case VAL_ELEM_IP:
	{
#ifdef HAVE_INET_NTOA
	  struct in_addr ia;

	  if (inet_aton (c, &ia))
	    *elem->val.v_ip = ia.s_addr;
#else
#warning "inet_ntoa not support. Support for VAL_ELEM_IP disabled."
#endif
	  break;
	}
    }
  };

  free (buffer);
  fclose (fp);

  return 0;
}

value_collection_t *value_create (unsigned char *name)
{
  int i;
  value_collection_t *c;

  c = malloc (sizeof (value_collection_t));
  if (!c)
    return NULL;
  memset (c, 0, sizeof (value_collection_t));

  for (i = 0; i < CONFIG_HASHSIZE; i++) {
    c->valuelist[i].next = &c->valuelist[i];
    c->valuelist[i].prev = &c->valuelist[i];
  }

  c->value_sorted.onext = &c->value_sorted;
  c->value_sorted.oprev = &c->value_sorted;

  return c;
}
