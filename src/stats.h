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

#ifndef _STATS_H_
#define _STATS_H_

#include "defaults.h"
#include "value.h"

extern value_collection_t *statvalues;

typedef value_value_t stats_value_t;
typedef value_element_t stats_element_t;

extern int stats_init ();
extern stats_element_t *stats_register (unsigned char *name, value_type_t type, void *,
					  const unsigned char *help);
extern int stats_unregister (unsigned char *name);
extern stats_element_t *stats_find (unsigned char *name);
extern void *stats_retrieve (unsigned char *name);
extern int stats_save (xml_node_t *);
extern int stats_load (xml_node_t *);

#endif /* _STATS_H_ */
