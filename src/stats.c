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

#include "stats.h"

value_collection_t *statvalues;

stats_element_t *stats_register (unsigned char *name, value_type_t type, void *ptr,
				 const unsigned char *help)
{
  return value_register (statvalues, name, type, ptr, help);
}

int stats_unregister (unsigned char *name)
{
  return value_unregister (statvalues, name);
}

stats_element_t *stats_find (unsigned char *name)
{
  return value_find (statvalues, name);
}

void *stats_retrieve (unsigned char *name)
{
  return value_retrieve (statvalues, name);
}

int stats_save (xml_node_t * base)
{
  return value_save (statvalues, base);
}

int stats_load (xml_node_t * node)
{
  return value_load (statvalues, node);
}

int stats_load_old (unsigned char *filename)
{
  return value_load_old (statvalues, filename);
}

int stats_init ()
{
  statvalues = value_create ("stats");

  return 0;
}
