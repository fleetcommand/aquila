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

#ifndef _BANLISTCLIENT_H_
#define _BANLISTCLIENT_H_

#include "../config.h"
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#include "config.h"
#include "buffer.h"
#include "dllist.h"

typedef struct banlist_client {
  dllist_entry_t dllist;

  unsigned char client[NICKLENGTH];
  double minVersion;
  double maxVersion;
  buffer_t *message;


} banlist_client_entry_t;

typedef dllist_t banlist_client_t;

extern banlist_client_entry_t *banlist_client_add (banlist_client_t * list, unsigned char *client,
						   double minVersion, double maxVersion,
						   buffer_t * reason);

extern unsigned int banlist_client_del (banlist_client_t * list, banlist_client_entry_t *);
extern unsigned int banlist_client_del_byclient (banlist_client_t * list, unsigned char *client, double min, double max);

extern banlist_client_entry_t *banlist_client_find (banlist_client_t * list, unsigned char *client,
						    double version);

extern unsigned int banlist_client_cleanup (banlist_client_t * list);
extern void banlist_client_clear (banlist_client_t * list);

extern unsigned int banlist_client_save (banlist_client_t * list, xml_node_t *);
extern unsigned int banlist_client_load (banlist_client_t * list, xml_node_t *);

extern void banlist_client_init (banlist_client_t * list);

#endif /* _BANLISTCLIENT_H_ */
