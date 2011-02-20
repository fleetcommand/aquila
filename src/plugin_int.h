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

#ifndef _PLUGIN_INT_H_
#define _PLUGIN_INT_H_

typedef struct plugin_private plugin_private_t;

#include "plugin.h"
#include "hub.h"
#include "proto.h"

/* main data storage per plugin.*/
struct plugin {
  struct plugin *next, *prev;

  const char name[PLUGIN_NAME_LENGTH];
  unsigned long id;

  unsigned long privates;
  unsigned long events;
  unsigned long robots;
};

/* plugin callback info */
typedef struct plugin_event_request {
  struct plugin_event_request *next, *prev;

  plugin_t *plugin;
  plugin_event_handler_t *handler;
} plugin_event_request_t;

/* this struct stores private pointers of the modules for each user.
 * each module is only allowed a single pointer.
 * this approach does't limit the user sizes but makes handling runtime modules a 
 * bit harder. for now, no problem. FIXME
 */
struct plugin_private {
  struct plugin_private *next, *prev;

  plugin_user_t user;		/* plugin user data. filled at user creation. a bit wastefull, but it prevents exporting the user_t */
  plugin_event_handler_t *handler;	/* for robots. */
  unsigned long num;		/* number of private pointers */
  user_t *parent;
  proto_t *proto;

  void **store;			/* private pointers for all modules. */
};

/* the main module manager data */
typedef struct plugin_manager {
  plugin_t plugins;		/* all loaded plugins */
  plugin_private_t privates;	/* all active private data */
  unsigned long num;		/* number of loaded plugins */

  plugin_event_request_t eventhandles[PLUGIN_EVENT_NUMBER];	/* all handlers, per event */
} plugin_manager_t;


/* internal entrypoints */

extern unsigned long plugin_send_event (plugin_private_t *, unsigned long, void *);
extern unsigned long plugin_new_user (plugin_private_t **, user_t * u, proto_t * p);
extern unsigned long plugin_del_user (plugin_private_t **);
extern unsigned long plugin_update_user (user_t * u);
extern int plugin_init ();

#endif
