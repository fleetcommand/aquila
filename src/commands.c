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
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "commands.h"
#include "hash.h"
#include "config.h"

plugin_t *cmdplug;

command_t cmd_hashtable[COMMAND_HASHTABLE];
command_t cmd_sorted;

/* FIXME check for duplicates */
int command_register (unsigned char *name, command_handler_t * handler, unsigned long long cap,
		      unsigned char *help)
{
  unsigned int hash = SuperFastHash (name, strlen (name));
  command_t *cmd;
  command_t *list = &cmd_hashtable[hash & COMMAND_HASHMASK];

  for (cmd = list->next; cmd != list; cmd = cmd->next)
    if (!strcmp (cmd->name, name))
      break;

  if (cmd != list)
    return -1;

  cmd = malloc (sizeof (command_t));
  memset (cmd, 0, sizeof (command_t));

  strncpy (cmd->name, name, COMMAND_MAX_LENGTH);
  cmd->name[COMMAND_MAX_LENGTH - 1] = 0;
  cmd->handler = handler;

  cmd->next = list->next;
  cmd->next->prev = cmd;
  cmd->prev = list;
  cmd->req_cap = cap;
  if (help)
    cmd->help = strdup (gettext (help));
  else
    cmd->help = strdup (__ ("No help available."));
  list->next = cmd;

  {
    /* add to ordered list */
    command_t *c;

    for (c = cmd_sorted.onext; c != &cmd_sorted; c = c->onext)
      if (strcmp (name, c->name) < 0)
	break;
    c = c->oprev;

    cmd->onext = c->onext;
    cmd->onext->oprev = cmd;
    cmd->oprev = c;
    c->onext = cmd;

  }

  return 0;
}

int command_setrights (unsigned char *name, unsigned long long cap, unsigned long long ncap)
{
  unsigned int hash = SuperFastHash (name, strlen (name));
  command_t *cmd;
  command_t *list = &cmd_hashtable[hash & COMMAND_HASHMASK];

  for (cmd = list->next; cmd != list; cmd = cmd->next)
    if (!strcmp (cmd->name, name))
      break;

  if (cmd == list)
    return 0;

  cmd->req_cap = ((cmd->req_cap | cap) & ~ncap);

  return 1;
}

int command_unregister (unsigned char *name)
{
  unsigned int hash = SuperFastHash (name, strlen (name));
  command_t *cmd;
  command_t *list = &cmd_hashtable[hash & COMMAND_HASHMASK];

  for (cmd = list->next; cmd != list; cmd = cmd->next)
    if (!strcmp (cmd->name, name))
      break;

  if (cmd == list)
    return 0;

  cmd->next->prev = cmd->prev;
  cmd->prev->next = cmd->next;

  if (cmd->help) {
    free (cmd->help);
    cmd->help = NULL;
  }

  {
    /* remove from ordered list */
    cmd->onext->oprev = cmd->oprev;
    cmd->oprev->onext = cmd->onext;
  }


  free (cmd);

  return 0;
}

unsigned long cmd_parser (plugin_user_t * user, plugin_user_t * target, void *priv,
			  unsigned long event, buffer_t * token)
{
  unsigned int hash, i;
  buffer_t *local;
  unsigned char *c, t, *d;
  unsigned int argc = 0;
  unsigned char *argv[COMMAND_MAX_ARGS + 1];
  command_t *cmd;
  command_t *list;

  memset (argv, 0, sizeof (unsigned char *) * COMMAND_MAX_ARGS);

  /* extract content from token. */
  c = token->s;
  c++;				/* skip < */
  while (*c && (*c != '>'))
    c++;
  if (!*c)
    return PLUGIN_RETVAL_DROP;
  c++;				/*  skip '>' */
  c++;				/* skip ' ' */

  /* check if command */
  if ((*c != '+') && (*c != '!'))
    return PLUGIN_RETVAL_CONTINUE;

  /* parse command. */
  DPRINTF ("CMD: %s\n", c);
  c++;

  /*  switch to local buffer copy so we can modify it. */
  local = bf_alloc (bf_used (token) + 1);
  *local->e = '\0';
  d = local->s;

  while (*c && (argc < (COMMAND_MAX_ARGS - 1))) {
    argv[argc] = d;
    /* if argument starts with a ' or a " include everything until next matching quote. */
    if ((*c == '\'') || (*c == '\"')) {
      t = *c++;
      while (*c) {
	if (*c == t)
	  break;
	if (*c == '\\') {
	  /* skip to next char and skip it if it isn't the \0 char */
	  if (!*++c)
	    break;
	}
	*d++ = *c++;
      }
      /* terminate after quote */
      if (*c == t) {
	c++;
	*d++ = '\0';
      }
    };
    /* skip until next space */
    while (*c && (*c != ' '))
      *d++ = *c++;

    /* replace space with terminator */
    if (*c)
      c++;

    *d++ = '\0';

    /* skip any following space */
    while (*c && (*c == ' '))
      c++;

    argc++;
  }
  local->e = d;

  if (!argc)
    goto leave;

  /* string wasn't completely parsed, but we are running out of argv spaces. all the rest in one argument. */
  if (*c && (argc == (COMMAND_MAX_ARGS - 1))) {
    argv[argc++] = d;
    bf_strcat (local, c);
  }

  for (i = argc; i <= COMMAND_MAX_ARGS; i++)
    argv[i] = NULL;

  /* look up command */
  hash = SuperFastHash (argv[0], strlen (argv[0]));
  list = &cmd_hashtable[hash & COMMAND_HASHMASK];
  for (cmd = list->next; cmd != list; cmd = cmd->next)
    if (!strcmp (cmd->name, argv[0]))
      break;

  /* execute handler */
  if ((cmd != list)
      && (!cmd->req_cap || ((user->rights & cmd->req_cap) == cmd->req_cap)
	  || (user->rights & CAP_OWNER))) {
    buffer_t *output = bf_alloc (10240);

    cmd->handler (user, output, priv, argc, argv);
    if (bf_used (output)) {
      if (target) {
	plugin_user_priv (target, user, NULL, output, 1);
      } else {
	plugin_user_sayto (NULL, user, output, 0);
      }
    }
    bf_free (output);
  } else {
    buffer_t *buf = bf_alloc (strlen (argv[0]) + 256);

    bf_printf (buf, _("Command not found: %s\n"), argv[0]);
    if (target) {
      plugin_user_priv (target, user, NULL, buf, 1);
    } else {
      plugin_user_sayto (NULL, user, buf, 0);
    }
    bf_free (buf);
  }

leave:
  /* free local copy */
  bf_free (local);

  /* do not display command to anyone. */
  return PLUGIN_RETVAL_DROP;
}

unsigned long cmd_parser_priv (plugin_user_t * user, void *priv, unsigned long event,
			       buffer_t * token)
{
  unsigned long retval;
  unsigned char *s = token->s, *c, *n;
  plugin_user_t *t;

  c = s + 5;
  n = s + 5;

  /* find source */
  for (; *c && (*c != ' '); c++);
  c += 7;
  n = c;
  for (; *c && (*c != ' '); c++);
  *c = '\0';

  t = plugin_user_find (n);
  if (!t)
    return PLUGIN_RETVAL_DROP;

  /* restore token */
  *c = ' ';

  /* skip pm part and parse command. */
  token->s = c + 2;
  retval = cmd_parser (t, user, priv, event, token);

  return retval;
}

unsigned long cmd_parser_main (plugin_user_t * user, void *priv, unsigned long event,
			       buffer_t * token)
{
  return cmd_parser (user, NULL, priv, event, token);
}

int command_setup ()
{
  config_element_t *hubsecnick;
  plugin_user_t *hubsec;

  hubsecnick = config_find ("hubsecurity.nick");

  hubsec = plugin_user_find (*hubsecnick->val.v_string);

  plugin_robot_set_handler (hubsec, &cmd_parser_priv);

  return 0;
}

int command_init ()
{
  int i;

  /* register plugin and request all chat messages */
  cmdplug = plugin_register ("CommandParser");
  plugin_request (cmdplug, PLUGIN_EVENT_CHAT, &cmd_parser_main);

  /* init hashtable */
  for (i = 0; i < COMMAND_HASHTABLE; i++) {
    cmd_hashtable[i].name[0] = '\0';
    cmd_hashtable[i].handler = NULL;
    cmd_hashtable[i].next = &cmd_hashtable[i];
    cmd_hashtable[i].prev = &cmd_hashtable[i];
  };

  cmd_sorted.onext = &cmd_sorted;
  cmd_sorted.oprev = &cmd_sorted;

  return 0;
}
