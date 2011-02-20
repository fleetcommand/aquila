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

#include "config.h"

value_collection_t *configvalues;

config_element_t *config_register (unsigned char *name, config_type_t type, void *ptr,
				   const unsigned char *help)
{
  return value_register (configvalues, name, type, ptr, help);
}

int config_unregister (unsigned char *name)
{
  return value_unregister (configvalues, name);
}

config_element_t *config_find (unsigned char *name)
{
  return value_find (configvalues, name);
}

void *config_retrieve (unsigned char *name)
{
  return value_retrieve (configvalues, name);
}

int config_save (xml_node_t * base)
{
  return value_save (configvalues, base);
}

int config_load (xml_node_t * node)
{
  return value_load (configvalues, node);
}

int config_load_old (unsigned char *filename)
{
  return value_load_old (configvalues, filename);
}

int config_init ()
{
  configvalues = value_create ("config");

  return 0;
}
