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

#ifndef _XML_H_
#define _XML_H_

#include <stdio.h>
#include "buffer.h"

typedef enum {
  XML_FLAG_FREEVALUE = 1,
  XML_FLAG_FREENAME  = 2
} xml_flag_t;

typedef enum { XML_TYPE_PTR,
  XML_TYPE_LONG, XML_TYPE_ULONG, XML_TYPE_CAP, XML_TYPE_ULONGLONG,
  XML_TYPE_INT, XML_TYPE_UINT,
  XML_TYPE_DOUBLE,
  XML_TYPE_STRING,
  XML_TYPE_IP,
  XML_TYPE_MEMSIZE,
  XML_TYPE_BYTESIZE
} xml_type_t;

typedef struct xml_attr {
  struct xml_attr *next, *prev;
  
  char *name;
  char *value;
} xml_attr_t;

typedef struct xml_node {
  struct xml_node *next, *prev;
  struct xml_node *parent, *children;

  xml_attr_t attr;

  xml_flag_t flags;

  char *name;
  char *value;
} xml_node_t;

extern xml_node_t *xml_node_add (xml_node_t *parent, char *name);
extern xml_node_t *xml_node_add_value (xml_node_t *parent, char *name, xml_type_t type, void *);
extern xml_node_t *xml_parent (xml_node_t *parent);

extern xml_attr_t *xml_attr_add (xml_node_t * node, unsigned char *name, unsigned char *value);
extern xml_attr_t *xml_attr_find (xml_node_t * node, char *name);
extern void xml_attr_del (xml_attr_t * attr);
extern xml_attr_t *xml_node_attr_get (xml_node_t * node, unsigned char *name, unsigned char **value);

extern xml_node_t *xml_node_find (xml_node_t *parent, char *name);
extern xml_node_t *xml_node_find_next (xml_node_t *sibling, char *name);
extern xml_node_t *xml_next (xml_node_t *sibling);

extern xml_node_t *xml_node_get (xml_node_t *node, xml_type_t type, void *);
extern xml_node_t *xml_child_get (xml_node_t *parent, char *name, xml_type_t type, void *);

extern xml_node_t *xml_import (buffer_t *buf);
extern buffer_t *xml_export (xml_node_t *);
extern xml_node_t *xml_read (FILE *);
extern unsigned long xml_write (FILE *, xml_node_t *);

extern unsigned int xml_free (xml_node_t *tree);

#endif
