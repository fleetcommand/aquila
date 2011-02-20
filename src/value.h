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

#ifndef _VALUE_H_
#define _VALUE_H_

#include "defaults.h"

#include "xml.h"

typedef enum { VAL_ELEM_PTR,
  VAL_ELEM_LONG, VAL_ELEM_ULONG, VAL_ELEM_CAP, VAL_ELEM_ULONGLONG,
  VAL_ELEM_INT, VAL_ELEM_UINT,
  VAL_ELEM_DOUBLE,
  VAL_ELEM_STRING,
  VAL_ELEM_IP,
  VAL_ELEM_MEMSIZE,
  VAL_ELEM_BYTESIZE
} value_type_t;

typedef union value_value {
    void **v_ptr;
    long *v_long;
    unsigned long *v_ulong;
    unsigned long long *v_ulonglong;
    unsigned long long *v_cap;
    unsigned long *v_ip;
    int *v_int;
    unsigned int *v_uint;
    double *v_double;
    unsigned char **v_string;
  } value_value_t;


typedef struct value_element {
  struct value_element *next, *prev;
  struct value_element *onext, *oprev;

  unsigned char name[CONFIG_NAMELENGTH];
  value_type_t type;
  value_value_t val;

  const unsigned char *help;
} value_element_t;

typedef struct value_collection {
  unsigned char name[CONFIG_NAMELENGTH];

  value_element_t valuelist[CONFIG_HASHSIZE];
  value_element_t value_sorted; 
} value_collection_t;

extern value_collection_t *value_create (unsigned char *name);
extern value_element_t *value_register (value_collection_t *collection, unsigned char *name, value_type_t type, void *,
					  const unsigned char *help);
extern int value_unregister (value_collection_t *collection, unsigned char *name);
extern value_element_t *value_find (value_collection_t *collection, unsigned char *name);
extern void *value_retrieve (value_collection_t *collection, unsigned char *name);
extern int value_save (value_collection_t *collection, xml_node_t *);
extern int value_load (value_collection_t *collection, xml_node_t *);

#endif /* _CONFIG_H_ */
