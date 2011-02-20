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
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "config.h"
#include "plugin.h"

#ifdef USE_WINDOWS
#  include "sys_windows.h"
#endif

typedef struct configlock {
  struct configlock *next;

  unsigned char name[CONFIG_NAMELENGTH];
  config_element_t *elem;
  union {
    void *v_ptr;
    long v_long;
    unsigned long v_ulong;
    unsigned long long v_ulonglong;
    unsigned long v_cap;
    unsigned long v_ip;
    int v_int;
    unsigned int v_uint;
    double v_double;
    unsigned char *v_string;
  } data;

} configlock_t;

unsigned char *filename = "configlock.conf";
configlock_t *locklist = NULL;
plugin_t *plugin_configlock;

unsigned long pi_configlock_event_load_old (plugin_user_t * user, void *dummy, unsigned long event,
					    buffer_t * token)
{
  FILE *fp;
  unsigned long l;
  char buffer[1024], *c;
  configlock_t *lock;
  config_element_t *elem;

  while (locklist) {
    lock = locklist;
    locklist = locklist->next;
    free (lock);
  }

  config_load_old (filename);

  fp = fopen (filename, "r");
  if (!fp)
    return PLUGIN_RETVAL_CONTINUE;

  while (fgets (buffer, 1024, fp)) {
    for (c = buffer; *c && *c != ' '; c++);
    if (!*c)
      continue;
    *c++ = '\0';
    elem = config_find (buffer);
    if (!elem)
      continue;

    lock = malloc (sizeof (configlock_t));
    memset (lock, 0, sizeof (configlock_t));

    lock->elem = elem;
    strncpy (lock->name, elem->name, CONFIG_NAMELENGTH);
    switch (elem->type) {
      case CFG_ELEM_PTR:
	sscanf (c, "%p", &lock->data.v_ptr);
	break;
      case CFG_ELEM_LONG:
	sscanf (c, "%ld", &lock->data.v_long);
	break;
      case CFG_ELEM_ULONG:
      case CFG_ELEM_CAP:
      case CFG_ELEM_MEMSIZE:
	sscanf (c, "%lu", &lock->data.v_ulong);
	break;
      case CFG_ELEM_BYTESIZE:
      case CFG_ELEM_ULONGLONG:
#ifndef USE_WINDOWS
	sscanf (c, "%Lu", &lock->data.v_ulonglong);
#else
	sscanf (c, "%I64u", &lock->data.v_ulonglong);
#endif
	break;
      case CFG_ELEM_INT:
	sscanf (c, "%d", &lock->data.v_int);
	break;
      case CFG_ELEM_UINT:
	sscanf (c, "%u", &lock->data.v_uint);
	break;
      case CFG_ELEM_DOUBLE:
	sscanf (c, "%lf", &lock->data.v_double);
	break;
      case CFG_ELEM_STRING:
	if (lock->data.v_string)
	  free (lock->data.v_string);
	l = strlen (c);
	if (c[l - 1] == '\n')
	  c[l-- - 1] = '\0';
	if ((*c == '"') && (c[l - 1] == '"')) {
	  c[l - 1] = '\0';
	  c++;
	};
	lock->data.v_string = string_unescape (c);
	break;
      case CFG_ELEM_IP:
	{
#ifdef HAVE_INET_NTOA
	  struct in_addr ia;

	  if (inet_aton (c, &ia))
	    lock->data.v_ip = ia.s_addr;
#else
#warning "inet_ntoa not support. Support for CFG_ELEM_IP disabled."
#endif
	  break;
	}
    }
    lock->next = locklist;
    locklist = lock;
  }
  fclose (fp);

  return PLUGIN_RETVAL_CONTINUE;
}

unsigned long pi_configlock_event_load (plugin_user_t * user, void *dummy, unsigned long event,
					void *arg)
{
  FILE *fp;
  configlock_t *lock;
  config_element_t *elem;
  xml_node_t *base, *node;

  if (!arg)
    goto leave;

  while (locklist) {
    lock = locklist;
    locklist = locklist->next;
    free (lock);
  }

  fp = fopen ("configlock.xml", "r");
  if (!fp)
    goto leave;

  base = xml_read (fp);
  if (!base) {
    fclose (fp);
    goto leave;
  }

  if (strcmp (base->name, HUBSOFT_NAME)) {
    xml_free (base);
    goto leave;
  }

  config_load (base);

  node = xml_node_find (base, "Config");
  for (node = node->children; node; node = xml_next (node)) {
    elem = config_find (node->name);
    if (!elem)
      continue;

    lock = malloc (sizeof (configlock_t));
    memset (lock, 0, sizeof (configlock_t));

    lock->elem = elem;
    strncpy (lock->name, elem->name, CONFIG_NAMELENGTH);

    xml_node_get (node, elem->type, &lock->data.v_ptr);

    lock->next = locklist;
    locklist = lock;
  }

  xml_free (base);

  fclose (fp);

  return PLUGIN_RETVAL_CONTINUE;

leave:
  return pi_configlock_event_load_old (user, dummy, event, NULL);
}

unsigned long pi_configlock_event_config (plugin_user_t * user, void *dummy, unsigned long event,
					  config_element_t * elem)
{
  configlock_t *lock;

  for (lock = locklist; lock && (lock->elem != elem); lock = lock->next);

  if (!lock)
    return PLUGIN_RETVAL_CONTINUE;

  switch (elem->type) {
    case CFG_ELEM_PTR:
      *elem->val.v_ptr = lock->data.v_ptr;
      break;
    case CFG_ELEM_LONG:
      *elem->val.v_long = lock->data.v_long;
      break;
    case CFG_ELEM_ULONG:
    case CFG_ELEM_CAP:
    case CFG_ELEM_MEMSIZE:
      *elem->val.v_ulong = lock->data.v_ulong;
      break;
    case CFG_ELEM_BYTESIZE:
    case CFG_ELEM_ULONGLONG:
      *elem->val.v_ulonglong = lock->data.v_ulonglong;
      break;
    case CFG_ELEM_INT:
      *elem->val.v_int = lock->data.v_int;
      break;
    case CFG_ELEM_UINT:
      *elem->val.v_uint = lock->data.v_uint;
      break;
    case CFG_ELEM_DOUBLE:
      *elem->val.v_double = lock->data.v_double;
      break;
    case CFG_ELEM_STRING:
      if (*elem->val.v_string)
	free (*elem->val.v_string);
      *elem->val.v_string = strdup (lock->data.v_ptr);
      break;
    case CFG_ELEM_IP:
      *elem->val.v_ip = lock->data.v_ip;
      break;
  }

  return PLUGIN_RETVAL_DROP;
}


/********************************* INIT *************************************/

int pi_configlock_init ()
{
  plugin_configlock = plugin_register ("configlock");

  plugin_request (plugin_configlock, PLUGIN_EVENT_CONFIG, (void *) &pi_configlock_event_config);
  plugin_request (plugin_configlock, PLUGIN_EVENT_LOAD, (void *) &pi_configlock_event_load);

  return 0;
}
