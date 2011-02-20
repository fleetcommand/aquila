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

#include "xml.h"

#include <string.h>
#include <ctype.h>
#include <limits.h>

#ifndef USE_WINDOWS
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#  ifdef HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#  endif
#else
#  include "sys_windows.h"
#endif

#include "commands.h"
#include "utils.h"

#define IMPORT_BUFSIZE 10000

buffer_t *xml_escape (buffer_t * target, unsigned char *src)
{
  for (; *src; src++) {
    switch (*src) {
      case '<':
	target = bf_printf_resize (target, "&lt;");
	break;
      case '>':
	target = bf_printf_resize (target, "&gt;");
	break;
      case '&':
	target = bf_printf_resize (target, "&amp;");
	break;
      default:
	if (bf_unused (target) < 2) {
	  target = bf_printf_resize (target, "%c", *src);
	} else {
	  *target->e++ = *src;
	  *target->e = 0;
	}
	break;
    }
  }
  return target;
}

unsigned char *xml_unescape (buffer_t * target, unsigned char *src)
{
  for (; *src; src++) {
    switch (*src) {
      case '&':
	src++;
	switch (*src) {
	  case 'l':
	    bf_strncat (target, "<", 1);
	    src += 2;
	    break;
	  case 'g':
	    bf_strncat (target, ">", 1);
	    src += 2;
	    break;
	  case 'a':
	    bf_strncat (target, "&", 1);
	    src += 3;
	    break;
	  case '#':
	    {
	      unsigned char c[2], *e;

	      c[0] = atoi (src + 1);
	      c[1] = 0;
	      e = strchr (src, ';');
	      if (e)
		src = e;
	      bf_strncat (target, c, 1);
	    }
	    break;
	}
	break;
      default:
	bf_strncat (target, src, 1);
    }
  }
  return 0;
}

xml_attr_t *xml_attr_add (xml_node_t * node, unsigned char *name, unsigned char *value)
{
  xml_attr_t *attr;

  attr = malloc (sizeof (xml_attr_t));
  if (!attr)
    return NULL;

  memset (attr, 0, sizeof (xml_attr_t));
  attr->name = strdup (name);
  attr->value = strdup (value);

  attr->next = &node->attr;
  attr->prev = node->attr.prev;
  attr->next->prev = attr;
  attr->prev->next = attr;

  return attr;
}

xml_attr_t *xml_attr_find (xml_node_t * node, char *name)
{
  xml_attr_t *attr;

  for (attr = node->attr.next; attr != &node->attr; attr = attr->next)
    if (!strcmp (name, attr->name))
      return attr;

  return NULL;
}

void xml_attr_del (xml_attr_t * attr)
{
  attr->next->prev = attr->prev;
  attr->prev->next = attr->next;
  free (attr->name);
  free (attr->value);
  free (attr);
}

xml_attr_t *xml_node_attr_get (xml_node_t * node, unsigned char *name, unsigned char **value)
{
  xml_attr_t *attr = xml_attr_find (node, name);

  if (!attr)
    return NULL;

  if (*value)
    free (*value);
  *value = strdup (attr->value);

  return attr;
}


unsigned int xml_free (xml_node_t * tree)
{
  xml_node_t *next;

  if (!tree)
    return 0;

  /* break the chain */
  tree->prev->next = NULL;

  /* kill all siblings */
  for (; tree; tree = next) {
    next = tree->next;

    /* kill children */
    xml_free (tree->children);

    /* free the attributes */
    while (tree->attr.next != &tree->attr)
      xml_attr_del (tree->attr.next);

    /* free node memory */
    if (tree->flags & XML_FLAG_FREEVALUE)
      free (tree->value);
    if (tree->flags & XML_FLAG_FREENAME)
      free (tree->name);
    free (tree);
  }
  return 0;
};

unsigned int xml_node_free (xml_node_t * node)
{
  xml_free (node->children);

  /* free node memory */
  if (node->flags & XML_FLAG_FREEVALUE)
    free (node->value);
  if (node->flags & XML_FLAG_FREENAME)
    free (node->name);
  free (node);

  return 0;
}

xml_node_t *xml_node_add (xml_node_t * parent, char *name)
{
  xml_node_t *node;

  node = malloc (sizeof (xml_node_t));
  if (!node)
    return NULL;

  memset (node, 0, sizeof (xml_node_t));
  node->name = strdup (name);
  node->flags |= XML_FLAG_FREENAME;
  node->parent = parent;

  node->attr.next = &node->attr;
  node->attr.prev = &node->attr;

  if (parent && parent->children) {
    node->next = parent->children;
    node->prev = node->next->prev;
    node->next->prev = node;
    node->prev->next = node;
  } else {
    node->next = node;
    node->prev = node;
    if (parent)
      parent->children = node;
  }

  return node;
};

xml_node_t *xml_node_add_value (xml_node_t * parent, char *name, xml_type_t type, void *value)
{
  xml_node_t *node = xml_node_add (parent, name);
  buffer_t *buf, *t;

  if (!node)
    return NULL;

  buf = bf_alloc (10240);

  switch (type) {
    case XML_TYPE_PTR:
      bf_printf_resize (buf, "%p", value);
      break;
    case XML_TYPE_LONG:
      bf_printf_resize (buf, "%ld", *((long *) value));
      break;
    case XML_TYPE_ULONG:
    case XML_TYPE_MEMSIZE:
      bf_printf_resize (buf, "%lu", *((unsigned long *) value));
      break;
    case XML_TYPE_BYTESIZE:
    case XML_TYPE_ULONGLONG:
#ifndef USE_WINDOWS
      bf_printf_resize (buf, "%llu", *((unsigned long long *) value));
#else
      bf_printf_resize (buf, "%I64u", *((unsigned long long *) value));
#endif
      break;
    case XML_TYPE_CAP:
      flags_print ((Capabilities + CAP_PRINT_OFFSET), buf, *((unsigned long long *) value));
      break;
    case XML_TYPE_INT:
      bf_printf_resize (buf, "%d", *((int *) value));
      break;
    case XML_TYPE_UINT:
      bf_printf_resize (buf, "%u", *((unsigned int *) value));
      break;
    case XML_TYPE_DOUBLE:
      bf_printf_resize (buf, "%lf", *((double *) value));
      break;
    case XML_TYPE_STRING:
      bf_printf_resize (buf, "%s", value ? ((unsigned char *) value) : (unsigned char *) "");
      break;
    case XML_TYPE_IP:
      {
	struct in_addr ia;

	ia.s_addr = *((unsigned long *) value);
	bf_printf_resize (buf, "%s", inet_ntoa (ia));
      }
      break;
    default:
      bf_printf_resize (buf, _("!Unknown Type!\n"));
  }

  if (bf_size (buf) > bf_used (buf)) {
    t = buf;
    buf = bf_copy (buf, 1);
    *buf->e = 0;
    bf_free (t);
  }

  node->value = strdup (buf->s);
  node->flags |= XML_FLAG_FREEVALUE;
  bf_free (buf);

  return node;
};

__inline__ xml_node_t *xml_parent (xml_node_t * node)
{
  return node->parent;
};

__inline__ xml_node_t *xml_next (xml_node_t * sibling)
{
  sibling = sibling->next;
  return (sibling != sibling->parent->children) ? sibling : NULL;
}

xml_node_t *xml_node_find (xml_node_t * parent, char *name)
{
  xml_node_t *node;

  node = parent->children;
  do {
    if (!strcmp (name, node->name))
      return node;

    node = node->next;
  } while (node != parent->children);

  return NULL;
};

xml_node_t *xml_node_find_next (xml_node_t * sibling, char *name)
{
  xml_node_t *node;

  node = sibling->next;
  while (node != sibling->parent->children) {
    if (!strcmp (name, node->name))
      return node;

    node = node->next;
  };

  return NULL;
};

xml_node_t *xml_node_get (xml_node_t * node, xml_type_t type, void *value)
{

  switch (type) {
    case XML_TYPE_PTR:
      sscanf (node->value, "%p", (void **) value);
      break;
    case XML_TYPE_LONG:
      sscanf (node->value, "%ld", (long *) value);
      break;
    case XML_TYPE_ULONG:
      sscanf (node->value, "%lu", (unsigned long *) value);
      break;
    case XML_TYPE_ULONGLONG:
#ifndef USE_WINDOWS
      sscanf (node->value, "%Lu", (unsigned long long *) value);
#else
      sscanf (node->value, "%I64u", (unsigned long long *) value);
#endif
      break;
    case XML_TYPE_CAP:
      {
	unsigned long long cap = 0, ncap = 0;
	unsigned char *argv[2];

	argv[0] = node->value;
	argv[1] = NULL;

	flags_parse (Capabilities, NULL, 1, argv, 0, &cap, &ncap);

	*((unsigned long long *) value) = cap;
	*((unsigned long long *) value) &= ~ncap;
      }
      break;
    case XML_TYPE_INT:
      sscanf (node->value, "%d", (int *) value);
      break;
    case XML_TYPE_UINT:
      sscanf (node->value, "%u", (unsigned int *) value);
      break;
    case XML_TYPE_DOUBLE:
      sscanf (node->value, "%lf", (double *) value);
      break;
    case XML_TYPE_STRING:
      if (*((unsigned char **) value))
	free (*((unsigned char **) value));
      *((unsigned char **) value) = strdup (node->value);
      break;
    case XML_TYPE_IP:
      {
	struct in_addr ia;

	if (!inet_aton (node->value, &ia))
	  break;

	*((unsigned long *) value) = ia.s_addr;
      }
      break;
    case XML_TYPE_MEMSIZE:
      {
	unsigned long long tmp = parse_size (node->value);

	if (tmp > ULONG_MAX)
	  break;

	*((unsigned long *) value) = tmp;
      }
      break;
    case XML_TYPE_BYTESIZE:
      *((unsigned long long *) value) = parse_size (node->value);
      break;
  }
  return node;
};

xml_node_t *xml_child_get (xml_node_t * parent, char *name, xml_type_t type, void *value)
{
  xml_node_t *child = xml_node_find (parent, name);

  if (!child)
    return NULL;

  return xml_node_get (child, type, value);
}


int xml_import_attr (xml_node_t * node, unsigned char *attr)
{
  unsigned int cont = 1;
  unsigned char *c, *e, *v;

  c = attr;

  while (cont) {
    /* skip any whitespace */
    while (*c && isspace (*c))
      c++;
    if (!*c)
      break;
    e = c;

    /* find end of attribute */
    while (*e && !isspace (*e))
      e++;

    /* mark end of attribute */
    if (!*e)
      cont = 0;
    *e = '\0';

    /* find = */
    v = c;
    while ((v < e) && (*v != '='))
      v++;

    /* must be there. */
    if (v == e)
      goto fail;

    /* replace = with 0 to seperate name and value */
    *v++ = '\0';

    /* detect and remove start and end " or ' */
    if ((*v == '"') || (*v = '\'')) {
      v++;
      *(e - 1) = 0;
    }

    /* create the node. */
    xml_attr_add (node, c, v);

    c = ++e;
  }

  return 0;

fail:
  return -1;
}

unsigned char *xml_import_element (xml_node_t ** parent, unsigned char *c, unsigned char *end)
{
  xml_node_t *node = NULL;
  unsigned char *e, *name, *attr, *value = NULL;

restart:
  /* skip whitespace */
  while (isspace (*c) && (c != end))
    c++;
  if (c == end)
    return NULL;

  /* verify start of tag */
  if (*c != '<')
    return NULL;

  /* skip comments */
  if (!strncmp (c, "<!--", 4)) {
    c = strstr (c, "-->");
    c += 3;
    goto restart;
  }
  if (!strncmp (c, "<?xml", 5)) {
    c = strstr (c, "?>");
    c += 2;
    goto restart;
  }

  c++;

  /* find end of tag */
  e = c;
  while ((*e != '>') && (e != end))
    e++;
  if (e == end)
    return NULL;

  /* find element name: find first space or closing bracket */
  name = c;
  while (!isspace (*c) && !(*c == '>') && (c != end))
    c++;
  if (c == end)
    return NULL;

  /* store attribute location */
  if ((*c != '>') && *c) {
    /* +1 so we skip the \0 we add below */
    attr = c + 1;
  } else
    attr = NULL;

  *c++ = 0;
  *e = 0;

  /* single tag element, no contents */
  if (*(e - 1) == '/') {
    /* nuke / */
    *(e - 1) = 0;

    /* create node */
    node = xml_node_add (*parent, name);

    /* parse attr */
    if (attr)
      xml_import_attr (node, attr);

    /* remove trailing whitespace */
    e++;
    while (isspace (*e) && e != end)
      e++;

    if (!*parent)
      *parent = node;

    return e;
  }

  /* parse contents */
  c = e + 1;

  /* skip whitespace */
  while (isspace (*c) && c != end)
    c++;
  if (c == end)
    return NULL;

  /* data element or tree element ? */
  if ((*c == '<') && (*(c + 1) != '/')) {
    if ((*(c + 1) != '!') || (*(c + 2) == '-')) {
      /* subnode (including <!-- --> comments */
      node = xml_node_add (*parent, name);
      if (attr)
	xml_import_attr (node, attr);
      while ((*c == '<') && (*(c + 1) != '/')) {
	c = xml_import_element (&node, c, end);
	if (!c || (c == end))
	  goto leave;
      }
    } else {
      /* CDATA element */
      if (strncmp (c, "<![CDATA[", 9))
	goto leave;
      c += 9;
      value = c;
      c = strstr (c, "]]>");
      if (!c)
	goto leave;
      *c = 0;
      c += 3;
    }
  } else {
    /* plain data element */
    value = c;
  }

  /* find end tag */
  while ((*c != '<') && (c != end))
    c++;
  if (c == end)
    goto leave;
  *c++ = 0;

  /* verify end of tag */
  if (*c != '/')
    goto leave;
  c++;

  /* verify tagname */
  if (strncmp (c, name, strlen (name)))
    goto leave;

  /* if it wasn't a tree element and it wasn't a single tag, 
     we need to create the data node now */
  if (!node) {
    buffer_t *buf = bf_alloc (c - value + 1);

    xml_unescape (buf, value);
    *buf->e = 0;

    node = xml_node_add_value (*parent, name, XML_TYPE_STRING, buf->s);

    bf_free (buf);

    if (attr)
      xml_import_attr (node, attr);
  }

  /* skip to end of tag and any trailing whitespace */
  while ((*c != '>') && (c != end))
    c++;
  if (c == end)
    return NULL;
  c++;
  while (isspace (*c) && c != end)
    c++;

  if (!*parent)
    *parent = node;

  return c;

leave:
  if (node && !*parent)
    xml_node_free (node);
  return NULL;
}

xml_node_t *xml_import (buffer_t * buf)
{
  xml_node_t *tree = NULL;

  xml_import_element (&tree, buf->s, buf->e);

  return tree;
};

buffer_t *xml_export_element (xml_node_t * node, buffer_t * buf, int level)
{
  xml_node_t *child;

  if (!node)
    return buf;

  if (node->value) {
    buf = bf_printf_resize (buf, "%*s<%s", level, "", node->name);
    /* FIXME add attr */
    buf = bf_printf_resize (buf, ">");
    buf = xml_escape (buf, node->value);
    buf = bf_printf_resize (buf, "</%s>\n", node->name);
    return buf;
  }

  if (!node->children) {
    buf = bf_printf_resize (buf, "%*s<%s ", level, "", node->name);
    /* FIXME add attr */
    buf = bf_printf_resize (buf, "/>\n");
    return buf;
  }

  buf = bf_printf_resize (buf, "%*s<%s>\n", level, "", node->name);
  if (node->children) {
    child = node->children;
    do {
      buf = xml_export_element (child, buf, level + 2);
      child = child->next;
    } while (child != node->children);
  }
  buf = bf_printf_resize (buf, "%*s</%s>\n", level, "", node->name);

  return buf;
}

buffer_t *xml_export (xml_node_t * tree)
{
  buffer_t *buf = bf_alloc (IMPORT_BUFSIZE);

  xml_export_element (tree, buf, 0);

  return buf;
};

xml_node_t *xml_read (FILE * fp)
{
  xml_node_t *node;
  buffer_t *buf;
  unsigned long offset, length;

  offset = ftell (fp);
  fseek (fp, 0, SEEK_END);
  length = ftell (fp) - offset;
  fseek (fp, offset, SEEK_SET);

  buf = bf_alloc (length + 1);

  buf->e += fread (buf->s, 1, length, fp);
  *buf->e++ = 0;
  node = xml_import (buf);

  bf_free (buf);

  return node;
};

unsigned long xml_write (FILE * fp, xml_node_t * tree)
{
  unsigned long l = 0;
  buffer_t *b, *buf;

  fwrite ("<?xml version=\"1.1\" ?>\n", 1, 23, fp);
  buf = xml_export (tree);
  b = buf;
  while (b) {
    if (bf_used (b))
      l += fwrite (b->s, 1, bf_used (b), fp);
    b = b->next;
  };

  bf_free (buf);

  return l;
};
