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

#include "hub.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "plugin.h"
#include "user.h"
#include "commands.h"
#include "proto.h"
#include "stringlist.h"

/*********************************************************************************************/

plugin_t *plugin_chatlog = NULL;
string_list_t chatlog;
unsigned long chatlogmax = 0;

/*********************************************************************************************/

unsigned long pi_chatlog_handler_chatlog (plugin_user_t * user, buffer_t * output, void *dummy,
					  unsigned int argc, unsigned char **argv)
{
  buffer_t *b;
  string_list_entry_t *e;

  if (!chatlogmax) {
    bf_printf (output, _("No Chat History configured.\n"));
    return 0;
  }

  bf_printf (output, _("Chat History:\n"));

  if (bf_unused (output) < (chatlog.size + chatlog.count)) {
    b = bf_alloc (chatlog.size + chatlog.count);
    bf_append (&output, b);
  } else {
    b = output;
  }
  for (e = chatlog.first; e; e = e->next)
    bf_printf (b, "%.*s\n", bf_used (e->data), e->data->s);

  return 0;
}

unsigned long pi_chatlog_handler_chat (plugin_user_t * user, void *priv, unsigned long event,
				       buffer_t * token)
{
  unsigned char *c;
  buffer_t *b;
  time_t t;
  struct tm *tmp;

  /* ignore event if no chatlog is configured */
  if (!chatlogmax)
    return PLUGIN_RETVAL_CONTINUE;

  /* skip any and all commands */
  for (c = token->s; *c && (*c != '>'); c++);
  c += 2;
  if ((*c == '!') || (*c == '+'))
    return PLUGIN_RETVAL_CONTINUE;

  /* allocate buffer */
  b = bf_alloc (bf_used (token) + 12);
  *b->e = '\0';

  /* add timestamp */
  time (&t);
  tmp = localtime (&t);
  b->e += strftime (b->s, b->size, "[%H:%M:%S] ", tmp);

  /* add chat message */
  bf_printf (b, "%.*s", bf_used (token), token->s);

  /* queue message */
  string_list_add (&chatlog, NULL, b);

  /* release scratch buffer */
  bf_free (b);

  /* delete any overflow */
  while (chatlog.count > chatlogmax)
    string_list_del (&chatlog, chatlog.first);

  return PLUGIN_RETVAL_CONTINUE;
}

/********************************* INIT *************************************/

int pi_chatlog_init ()
{
  plugin_chatlog = plugin_register ("chatlog");

  string_list_init (&chatlog);

  plugin_request (plugin_chatlog, PLUGIN_EVENT_CHAT, &pi_chatlog_handler_chat);

  config_register ("chatlog.lines", CFG_ELEM_ULONG, &chatlogmax,
		   _("Maximum number of chat history lines."));

  command_register ("chatlog", &pi_chatlog_handler_chatlog, 0,
		    _("Command returns last chatlines."));

  return 0;
}
