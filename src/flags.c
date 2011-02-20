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

#include <ctype.h>

#include "flags.h"
#include "defaults.h"

unsigned int flags_print (flag_t * flags, buffer_t * buf, unsigned long long flag)
{
  unsigned int cnt = 0, j;

  if (!flag) {
    bf_printf (buf, _("None"));
    return 0;
  }

  for (j = 0; flags[j].name != 0; j++) {
    if (!flags[j].flag)
      continue;
    if ((flags[j].flag & flag) == flags[j].flag) {
      bf_printf (buf, "%s,", flags[j].name);
      cnt++;
    }
  }
  if (cnt) {
    buf->e--;
    *buf->e = '\0';
  }

  return 0;
}

unsigned int flags_help (flag_t * flags, buffer_t * buf)
{
  unsigned int j;

  for (j = 0; flags[j].name != 0; j++) {
    if (!flags[j].flag)
      continue;
    bf_printf (buf, "%s : %s\n", flags[j].name, gettext (flags[j].help));
  }

  return 0;
}

unsigned int flags_parse (flag_t * flags, buffer_t * buf, unsigned int argc,
			  unsigned char **argv, unsigned int flagstart, unsigned long long *flag,
			  unsigned long long *nflag)
{
  unsigned int i, j;
  unsigned char *name, *arg, *work;

  ASSERT (flag && nflag);
  for (i = flagstart; i < argc; i++) {
    work = strdup (argv[i]);

    name = strtok (work, ", ");

    while (name) {
      while (isspace (*name))
	name++;

      arg = name;
      if ((name[0] == '-') || (name[0]) == '+')
	name++;

      for (j = 0; flags[j].name; j++) {
	if (!flags[j].flag)
	  continue;
	if (!strcasecmp (flags[j].name, name)) {
	  if (arg[0] != '-') {
	    if (buf)
	      bf_printf (buf, _("Added %s.\n"), flags[j].name);
	    *flag |= flags[j].flag;
	    *nflag &= ~flags[j].flag;
	  } else {
	    if (buf)
	      bf_printf (buf, _("Removed %s.\n"), flags[j].name);
	    *nflag |= flags[j].flag;
	    *flag &= ~flags[j].flag;
	  }
	  break;
	}
      }
      if (buf && !flags[j].name)
	bf_printf (buf, _("Unknown %s.\n"), argv[i]);

      name = strtok (NULL, ", ");
    }

    free (work);
  }

  return 0;
}
