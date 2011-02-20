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
#include <ctype.h>
#include <string.h>

#include <sys/types.h>

#include "utils.h"

#ifndef __USE_W32_SOCKETS
#  include <sys/socket.h>
#endif

#include "buffer.h"
#include "gettext.h"

#ifdef USE_WINDOWS
#  include "sys_windows.h"
#endif

const char *units[] = { "Bytes", "Kilobyte", "Megabyte", "Gigabyte", "Terabyte", "Petabyte" };

unsigned char *format_size (unsigned long long size)
{
  static unsigned char buf[128];
  int i;
  double output;

  i = 0;
  output = size;
  while (((size >> 10) > 0) && (i < 5)) {
    i++;
    output = size;
    size = size >> 10;
    output = output / 1024;
  };

  snprintf (buf, 128, "%.3f %s", output, units[i]);

  return buf;
}

const unsigned char rev_units[] = "bkmgtp";

unsigned long long parse_size (unsigned char *token)
{
  char *t;
  int i;
  unsigned long long size = 0, mod = 1;

  size = strtoll (token, &t, 10);
  if (!*t)
    return size;

  for (mod = 1, i = 0; rev_units[i] && (*t != rev_units[i]); i++, mod *= 1024);
  if (!rev_units[i])
    return size;

  return size * mod;
}

char *time_print (unsigned long s)
{
  static char buffer[512];
  unsigned int weeks, days, hours, minutes, seconds, total;

  seconds = s % 60;
  minutes = s / 60;
  hours = minutes / 60;
  days = hours / 24;
  weeks = days / 7;
  minutes = minutes % 60;
  hours = hours % 24;
  days = days % 7;

  total = 0;

  if (weeks)
    total += snprintf (buffer, 512, ngettext ("%u week, ", "%u weeks, ", weeks), weeks);
  if (days)
    total += snprintf (buffer + total, 512 - total, ngettext ("%u day, ", "%u days, ", days), days);

  if ((hours || minutes || seconds) || (!(weeks || days)))
    total += snprintf (buffer + total, 512 - total, "%02u:%02u:%02u", hours, minutes, seconds);

  return buffer;
}

unsigned long time_parse (unsigned char *string)
{
  unsigned long total, reg;
  unsigned char *c;

  reg = 0;
  total = 0;
  c = string;
  while (*c && *c != ' ') {
    if (isdigit (*c)) {
      reg *= 10;
      reg += (*c - '0');
    } else if (isalpha (*c)) {
      switch (tolower (*c)) {
	case 'y':
	  reg *= 365 * 24 * 60 * 60;
	  break;
	case 'w':
	  reg *= 7 * 24 * 60 * 60;
	  break;
	case 'd':
	  reg *= 24 * 60 * 60;
	  break;
	case 'h':
	  reg *= 3600;
	  break;
	case 'm':
	  reg *= 60;
	  break;
	case 's':
	  break;
	default:
	  return 0;
      }
      total += reg;
      reg = 0;
    } else {
      /* stop interpreting on diff character */
      break;
    }
    c++;
  }
  /* plain numbers are interpreted as seconds. */
  if (reg)
    total += reg;

  return total;
}

unsigned char *print_ip (struct in_addr ip, struct in_addr netmask)
{
  unsigned char *t;
  static unsigned char buffer[256];

  t = buffer;
  t += snprintf (buffer, 255, "%s", inet_ntoa (ip));
  if (netmask.s_addr != 0xFFFFFFFF) {
    snprintf (t, 255 - (t - buffer), ":%s", inet_ntoa (netmask));
  };

  return buffer;
}

unsigned long parse_ip (unsigned char *text, struct in_addr *ip, struct in_addr *netmask)
{
  unsigned char *work;
  unsigned int retval = 1;
  unsigned char *elem;

  work = strdup (text);

  elem = strtok (work, ":/");
  if (elem) {
    retval = inet_aton (elem, ip);
    if (!retval)
      goto leave;
  }
  elem = strtok (NULL, ":/");
  if (elem) {
    if (text[(elem - work - 1)] == ':') {
      retval = inet_aton (elem, netmask);
      if (!retval)
	goto leave;
    } else {
      long i = strtol (elem, NULL, 10);

      if ((i < 0) || (i > 31)) {
	retval = 0;
	goto leave;
      }
      netmask->s_addr = 0;
      for (; i; --i)
	netmask->s_addr = (netmask->s_addr >> 1) | 0x80000000;

      netmask->s_addr = ntohl (netmask->s_addr);
    }
  } else {
    netmask->s_addr = 0xFFFFFFFF;
  }
leave:
  free (work);
  return retval;
}
unsigned char *string_escape (unsigned char *in)
{
  unsigned char *c;
  unsigned char *out;

  if (!in)
    return NULL;

  out = malloc (strlen (in) * 2 + 2);
  for (c = out; *in; in++) {
    switch (*in) {
      case '\\':
	*c++ = '\\';
	*c++ = '\\';
	break;
      case '\n':
	*c++ = '\\';
	*c++ = 'n';
	break;
      case '\"':
      case '\'':
	*c++ = '\\';
	*c++ = *in;
	break;
      default:
	*c++ = *in;
    }
  }
  *c++ = '\0';

  return out;
}

unsigned char *string_unescape (unsigned char *in)
{
  unsigned char *c;
  unsigned char *out;

  out = malloc (strlen (in) + 1);

  for (c = out; *in; in++) {
    switch (*in) {
      case '\\':
	++in;
	switch (*in) {
	  case 'n':
	    *c++ = '\n';
	    break;
	  default:
	    *c++ = *in;
	}
	break;
      default:
	*c++ = *in;
    }
  }
  *c = '\0';

  return out;
}
