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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <limits.h>
#ifdef __USE_W32_SOCKETS
#include <winsock2.h>
#endif
#include <sys/time.h>

#include "aqtime.h"
#include "plugin.h"
#include "config.h"
#include "commands.h"
#include "utils.h"

#ifdef USE_WINDOWS
#define stat _stat
#endif


#define TRIGGER_RELOAD_PERIOD   10

#define TRIGGER_NAME_LENGTH 	64

#define	TRIGGER_TYPE_FILE	1
#define TRIGGER_TYPE_COMMAND	2
#define TRIGGER_TYPE_TEXT	3

#define TRIGGER_FLAG_CACHED	1
#define TRIGGER_FLAG_READALWAYS 2


#define RULE_FLAG_PM		1
#define RULE_FLAG_BC		2

#define TRIGGER_RULE_LOGIN	1
#define TRIGGER_RULE_COMMAND	2
#define TRIGGER_RULE_TIMER	3

typedef struct trigger {
  struct trigger *next, *prev;

  unsigned char name[TRIGGER_NAME_LENGTH];
  unsigned long type;
  unsigned long flags;

  /* text stuff */
  buffer_t *text;

  /* file stuff */
  struct stat stat;
  unsigned char *file;

  /* cache stuff */
  unsigned long refcnt;
  unsigned long idcnt;
  unsigned long usecnt;
  struct timeval timestamp;
} trigger_t;

typedef struct trigger_rule {
  struct trigger_rule *next, *prev;

  trigger_t *trigger;
  unsigned long id;
  unsigned long type;
  unsigned char *arg;
  unsigned char *help;
  unsigned long long cap;
  unsigned long flags;
  unsigned long interval;
  unsigned long deadline;
} trigger_rule_t;

/* local data */
plugin_t *plugin_trigger = NULL;

trigger_t triggerList;
trigger_rule_t ruleListCommand;
trigger_rule_t ruleListLogin;
trigger_rule_t ruleListTimer;

unsigned long deadline = ULONG_MAX;

unsigned char *pi_trigger_SaveFile;

void trigger_rule_delete (trigger_rule_t * rule);

/************************************************************************************************/

unsigned int trigger_deadline ()
{
  trigger_rule_t *r;

  deadline = ULONG_MAX;
  for (r = ruleListTimer.next; r != &ruleListTimer; r = r->next)
    if (r->deadline < deadline)
      deadline = r->deadline;

  return 0;
}

unsigned int trigger_cache (trigger_t * trigger)
{
  size_t n, l;
  FILE *fp;

  ASSERT (trigger->type == TRIGGER_TYPE_FILE);

  if (trigger->text)
    bf_free (trigger->text);

  /* if the size if 0, try with 10kByte to allow reading of "special" files */
  l = trigger->stat.st_size;
  if (!l)
    l = 10240;

  trigger->text = bf_alloc (l);
  if (!trigger->text)
    return 0;

  fp = fopen (trigger->file, "r");
  if (!fp) {
    plugin_perror ("ERROR loading trigger file %s", trigger->file);
    return errno;
  }

  n = fread (trigger->text->s, 1, l, fp);
  fclose (fp);

  trigger->text->e += n;

  trigger->flags |= TRIGGER_FLAG_CACHED;

  return n;
}

void trigger_verify (trigger_t * trigger)
{
  struct stat curstat;

  if (trigger->type == TRIGGER_TYPE_TEXT)
    return;

  switch (trigger->type) {
    case TRIGGER_TYPE_FILE:
      if ((now.tv_sec - trigger->timestamp.tv_sec) < TRIGGER_RELOAD_PERIOD)
	break;

      trigger->timestamp = now;

      if (!(trigger->flags & TRIGGER_FLAG_READALWAYS)) {
	if (stat (trigger->file, &curstat))
	  break;

	if (curstat.st_mtime == trigger->stat.st_mtime)
	  break;

	trigger->stat = curstat;
      }

      trigger_cache (trigger);

      break;
    case TRIGGER_TYPE_COMMAND:
      if ((now.tv_sec - trigger->timestamp.tv_sec) < TRIGGER_RELOAD_PERIOD)
	break;

      break;
    case TRIGGER_TYPE_TEXT:
      break;
  }
}



trigger_t *trigger_create (unsigned char *name, unsigned long type, unsigned char *arg)
{
  trigger_t *trigger;

  trigger = (trigger_t *) malloc (sizeof (trigger_t));
  if (!trigger)
    return NULL;

  memset (trigger, 0, sizeof (trigger_t));

  strncpy (trigger->name, name, TRIGGER_NAME_LENGTH);
  trigger->name[TRIGGER_NAME_LENGTH - 1] = 0;
  trigger->type = type;

  switch (type) {
    case TRIGGER_TYPE_FILE:
      trigger->file = strdup (arg);
      if (stat (trigger->file, &trigger->stat))
	goto error;

      trigger_cache (trigger);

      break;
    case TRIGGER_TYPE_COMMAND:
      trigger->file = strdup (arg);
      if (stat (trigger->file, &trigger->stat))
	goto error;

      /* is this a regular file ? */
      if (!(trigger->stat.st_mode & S_IFREG)) {
	errno = EINVAL;
	goto error;
      }
#ifndef USE_WINDOWS
      /* verify if executable  */
      if (trigger->stat.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
	errno = EINVAL;
	goto error;
      }
#endif

      /* ok... we will know if we have permission later... */
      break;
    case TRIGGER_TYPE_TEXT:
      trigger->text = bf_alloc (strlen (arg) + 1);
      bf_strcat (trigger->text, arg);
      break;
  }

  trigger->timestamp = now;

  /* link in list, at the end. */
  trigger->next = &triggerList;
  trigger->prev = triggerList.prev;
  trigger->next->prev = trigger;
  trigger->prev->next = trigger;

  return trigger;

error:
  if (trigger->text)
    bf_free (trigger->text);

  if (trigger->file)
    free (trigger->file);

  free (trigger);

  return NULL;
}

trigger_t *trigger_find (unsigned char *name)
{
  trigger_t *trigger;

  for (trigger = triggerList.next; trigger != &triggerList; trigger = trigger->next)
    if (!strcmp (trigger->name, name))
      return trigger;

  return NULL;
}

void trigger_delete (trigger_t * trigger)
{
  if (trigger->refcnt) {
    trigger_rule_t *rule, *next;

    for (rule = ruleListLogin.next; rule != &ruleListLogin; rule = next) {
      next = rule->next;
      if (rule->trigger == trigger)
	trigger_rule_delete (rule);
    };

    for (rule = ruleListCommand.next; rule != &ruleListCommand; rule = next) {
      next = rule->next;
      if (rule->trigger == trigger)
	trigger_rule_delete (rule);
    };

    for (rule = ruleListTimer.next; rule != &ruleListTimer; rule = next) {
      next = rule->next;
      if (rule->trigger == trigger)
	trigger_rule_delete (rule);
    };
  }

  trigger->next->prev = trigger->prev;
  trigger->prev->next = trigger->next;

  if (trigger->text)
    bf_free (trigger->text);

  if (trigger->file)
    free (trigger->file);

  free (trigger);
}

unsigned long pi_trigger_command (plugin_user_t * user, buffer_t * output, void *dummy,
				  unsigned int argc, unsigned char **argv)
{
  trigger_rule_t *r;
  plugin_user_t *tgt, *prev;

  for (r = ruleListCommand.next; r != &ruleListCommand; r = r->next) {
    if (strcmp (argv[0], r->arg))
      continue;

    r->trigger->usecnt++;

    trigger_verify (r->trigger);
    if (bf_used (r->trigger->text)) {
      switch (r->flags & (RULE_FLAG_PM | RULE_FLAG_BC)) {
	case RULE_FLAG_BC:
	  plugin_user_say (NULL, r->trigger->text);
	  break;
	case RULE_FLAG_PM:
	  plugin_user_priv (NULL, user, NULL, r->trigger->text, 0);
	  break;
	case RULE_FLAG_PM | RULE_FLAG_BC:
	  tgt = NULL;
	  prev = NULL;
	  while (plugin_user_next (&tgt)) {
	    prev = tgt;
	    if (plugin_user_priv (NULL, tgt, NULL, r->trigger->text, 0) < 0)
	      tgt = prev;
	  }
	  break;
	default:
	  bf_printf (output, "%.*s", bf_used (r->trigger->text), r->trigger->text->s);
      }
    }
    break;
  };

  return 0;
}

unsigned long pi_trigger_login (plugin_user_t * user, void *dummy, unsigned long event,
				buffer_t * token)
{
  trigger_rule_t *r;

  for (r = ruleListLogin.next; r != &ruleListLogin; r = r->next) {
    if ((r->cap & user->rights) != r->cap)
      continue;

    r->trigger->usecnt++;

    trigger_verify (r->trigger);
    if (bf_used (r->trigger->text)) {
      if (r->flags & RULE_FLAG_PM) {
	plugin_user_priv (NULL, user, NULL, r->trigger->text, 0);
      } else {
	plugin_user_sayto (NULL, user, r->trigger->text, 0);
      }
    }
  };

  return 0;
}

unsigned long pi_trigger_timer (plugin_user_t * user, void *dummy, unsigned long event,
				buffer_t * token)
{
  trigger_rule_t *r;
  plugin_user_t *tgt, *prev;

  if (((unsigned long) now.tv_sec) < deadline)
    return 0;

  for (r = ruleListTimer.next; r != &ruleListTimer; r = r->next) {
    if (r->deadline > deadline)
      continue;

    r->trigger->usecnt++;
    r->deadline += r->interval;

    trigger_verify (r->trigger);

    if (bf_used (r->trigger->text)) {
      tgt = NULL;
      prev = NULL;
      while (plugin_user_next (&tgt)) {
	prev = tgt;
	if ((tgt->rights & r->cap) != r->cap)
	  continue;
	if (r->flags & RULE_FLAG_PM) {
	  if (plugin_user_priv (NULL, tgt, NULL, r->trigger->text, 0) < 0)
	    tgt = prev;
	} else {
	  if (plugin_user_sayto (NULL, tgt, r->trigger->text, 0) < 0)
	    tgt = prev;
	}
      }
    }
  }

  trigger_deadline ();

  return 0;
}

trigger_rule_t *trigger_rule_create (trigger_t * t, unsigned long type, unsigned long long cap,
				     unsigned long flags, unsigned char *arg, unsigned char *help)
{
  trigger_rule_t *rule;
  trigger_rule_t *list;

  rule = (trigger_rule_t *) malloc (sizeof (trigger_rule_t));
  if (!rule)
    return NULL;

  memset (rule, 0, sizeof (trigger_rule_t));

  rule->trigger = t;
  rule->id = t->idcnt++;
  t->refcnt++;
  rule->type = type;
  rule->cap = cap;
  rule->flags |= flags;
  if (help) {
    rule->help = strdup (help);
  } else {
    rule->help = NULL;
  }

  switch (type) {
    case TRIGGER_RULE_LOGIN:
      rule->arg = NULL;
      list = &ruleListLogin;
      break;
    case TRIGGER_RULE_COMMAND:
      ASSERT (arg);
      rule->arg = strdup (arg);
      if (command_register (rule->arg, &pi_trigger_command, cap, rule->help) < 0) {
	free (rule);
	return NULL;
      }
      list = &ruleListCommand;
      break;
    case TRIGGER_RULE_TIMER:
      rule->interval = (unsigned long) arg;
      rule->deadline = now.tv_sec + rule->interval;
      rule->arg = NULL;
      list = &ruleListTimer;
      break;
    default:
      t->refcnt--;
      if (rule->help)
	free (rule->help);
      free (rule);
      return NULL;
  }

  /* link to list at the end; */
  rule->next = list;
  rule->prev = list->prev;
  rule->next->prev = rule;
  rule->prev->next = rule;

  if (type == TRIGGER_RULE_TIMER)
    trigger_deadline ();

  return rule;
}

trigger_rule_t *trigger_rule_find (trigger_t * t, unsigned long id)
{
  trigger_rule_t *rule;

  for (rule = ruleListLogin.next; rule != &ruleListLogin; rule = rule->next)
    if ((rule->trigger == t) && (rule->id == id))
      return rule;

  for (rule = ruleListCommand.next; rule != &ruleListCommand; rule = rule->next)
    if ((rule->trigger == t) && (rule->id == id))
      return rule;

  for (rule = ruleListTimer.next; rule != &ruleListTimer; rule = rule->next)
    if ((rule->trigger == t) && (rule->id == id))
      return rule;

  return NULL;
}

void trigger_rule_delete (trigger_rule_t * rule)
{
  rule->next->prev = rule->prev;
  rule->prev->next = rule->next;

  switch (rule->type) {
    case TRIGGER_RULE_COMMAND:
      command_unregister (rule->arg);
      free (rule->arg);
      break;
    case TRIGGER_RULE_TIMER:
      trigger_deadline ();
      break;
  }

  if (rule->help)
    free (rule->help);

  rule->trigger->refcnt--;

  free (rule);
}

int trigger_save (xml_node_t * node)
{
  trigger_t *trigger;
  trigger_rule_t *rule;

  node = xml_node_add (node, "TriggerConfig");

  node = xml_node_add (node, "Triggers");
  for (trigger = triggerList.next; trigger != &triggerList; trigger = trigger->next) {
    node = xml_node_add (node, "Trigger");
    xml_node_add_value (node, "Name", XML_TYPE_STRING, trigger->name);
    xml_node_add_value (node, "Type", XML_TYPE_ULONG, &trigger->type);
    switch (trigger->type) {
      case TRIGGER_TYPE_FILE:
	xml_node_add_value (node, "File", XML_TYPE_STRING, trigger->file);
	break;
      case TRIGGER_TYPE_TEXT:
	xml_node_add_value (node, "Text", XML_TYPE_STRING, trigger->text->s);
	break;
      case TRIGGER_TYPE_COMMAND:
	break;
    }
    node = xml_parent (node);
  }
  node = xml_parent (node);

  node = xml_node_add (node, "Rules");

  node = xml_node_add (node, "LoginRules");
  for (rule = ruleListLogin.next; rule != &ruleListLogin; rule = rule->next) {
    node = xml_node_add (node, "Rule");
    xml_node_add_value (node, "Name", XML_TYPE_STRING, rule->trigger->name);
    xml_node_add_value (node, "Type", XML_TYPE_ULONG, &rule->type);
    xml_node_add_value (node, "Rights", XML_TYPE_CAP, &rule->cap);
    xml_node_add_value (node, "Flags", XML_TYPE_ULONG, &rule->flags);
    node = xml_parent (node);
  }
  node = xml_parent (node);

  node = xml_node_add (node, "CommandRules");
  for (rule = ruleListCommand.next; rule != &ruleListCommand; rule = rule->next) {
    node = xml_node_add (node, "Rule");
    xml_node_add_value (node, "Name", XML_TYPE_STRING, rule->trigger->name);
    xml_node_add_value (node, "Type", XML_TYPE_ULONG, &rule->type);
    xml_node_add_value (node, "Rights", XML_TYPE_CAP, &rule->cap);
    xml_node_add_value (node, "Flags", XML_TYPE_ULONG, &rule->flags);
    xml_node_add_value (node, "Command", XML_TYPE_STRING, rule->arg);
    xml_node_add_value (node, "Help", XML_TYPE_STRING, rule->help ? (char *) rule->help : "");
    node = xml_parent (node);
  }
  node = xml_parent (node);

  node = xml_node_add (node, "TimerRules");
  for (rule = ruleListTimer.next; rule != &ruleListTimer; rule = rule->next) {
    node = xml_node_add (node, "Rule");
    xml_node_add_value (node, "Name", XML_TYPE_STRING, rule->trigger->name);
    xml_node_add_value (node, "Type", XML_TYPE_ULONG, &rule->type);
    xml_node_add_value (node, "Rights", XML_TYPE_CAP, &rule->cap);
    xml_node_add_value (node, "Flags", XML_TYPE_ULONG, &rule->flags);
    xml_node_add_value (node, "Interval", XML_TYPE_ULONG, &rule->interval);
    node = xml_parent (node);
  }
  node = xml_parent (node);

  return 0;
}

int trigger_load (xml_node_t * base)
{
  unsigned char *name = NULL, *arg = NULL, *help = NULL;
  unsigned long type = 0, flags = 0, interval = 0;
  unsigned long long rights = 0;
  trigger_t *trigger;
  xml_node_t *node = NULL;

  base = xml_node_find (base, "TriggerConfig");

  node = xml_node_find (base, "Triggers");
  for (node = node->children; node; node = xml_next (node)) {
    if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
      continue;
    if (!xml_child_get (node, "Type", XML_TYPE_ULONG, &type))
      continue;
    switch (type) {
      case TRIGGER_TYPE_FILE:
	if (!xml_child_get (node, "File", XML_TYPE_STRING, &arg))
	  continue;
	break;
      case TRIGGER_TYPE_TEXT:
	if (!xml_child_get (node, "Text", XML_TYPE_STRING, &arg))
	  continue;
	break;
    }
    trigger_create (name, type, arg);
  }

  base = xml_node_find (base, "Rules");

  node = xml_node_find (base, "LoginRules");
  for (node = node->children; node; node = xml_next (node)) {
    if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
      continue;
    if (!xml_child_get (node, "Type", XML_TYPE_ULONG, &type))
      continue;
    if (!xml_child_get (node, "Rights", XML_TYPE_CAP, &rights))
      continue;
    if (!xml_child_get (node, "Flags", XML_TYPE_ULONG, &flags))
      continue;

    trigger = trigger_find (name);
    if (!trigger)
      continue;
    trigger_rule_create (trigger, type, rights, flags, NULL, NULL);
  }

  node = xml_node_find (base, "CommandRules");
  for (node = node->children; node; node = xml_next (node)) {
    if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
      continue;
    if (!xml_child_get (node, "Type", XML_TYPE_ULONG, &type))
      continue;
    if (!xml_child_get (node, "Rights", XML_TYPE_CAP, &rights))
      continue;
    if (!xml_child_get (node, "Flags", XML_TYPE_ULONG, &flags))
      continue;
    if (!xml_child_get (node, "Command", XML_TYPE_STRING, &arg))
      continue;
    if (!xml_child_get (node, "Help", XML_TYPE_STRING, &help))
      continue;

    trigger = trigger_find (name);
    if (!trigger)
      continue;
    trigger_rule_create (trigger, type, rights, flags, arg, help);
  }

  node = xml_node_find (base, "TimerRules");
  for (node = node->children; node; node = xml_next (node)) {
    if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
      continue;
    if (!xml_child_get (node, "Type", XML_TYPE_ULONG, &type))
      continue;
    if (!xml_child_get (node, "Rights", XML_TYPE_CAP, &rights))
      continue;
    if (!xml_child_get (node, "Flags", XML_TYPE_ULONG, &flags))
      continue;
    if (!xml_child_get (node, "Interval", XML_TYPE_ULONG, &interval))
      continue;

    trigger = trigger_find (name);
    if (!trigger)
      continue;
    trigger_rule_create (trigger, type, rights, flags, (void *) interval, NULL);
  }

  if (name)
    free (name);
  if (arg)
    free (arg);
  if (help)
    free (help);

  return PLUGIN_RETVAL_CONTINUE;
}

int trigger_load_old (unsigned char *file)
{
  FILE *fp;
  unsigned char buffer[1024];
  unsigned char name[TRIGGER_NAME_LENGTH];
  unsigned char cmd[TRIGGER_NAME_LENGTH];
  unsigned long type, flags, cap, interval;
  int offset;
  unsigned int i;

  trigger_t *trigger;
  trigger_rule_t *rule;

  fp = fopen (file, "r+");
  if (!fp) {
    plugin_perror ("ERROR: loading file %s", file);
    return PLUGIN_RETVAL_CONTINUE;
  }

  fgets (buffer, sizeof (buffer), fp);
  while (!feof (fp)) {
    for (i = 0; buffer[i] && (buffer[i] != '\n') && (i < sizeof (buffer)); i++);
    if (i == sizeof (buffer))
      break;
    if (buffer[i] == '\n')
      buffer[i] = '\0';

    flags = 0;
    switch (buffer[0]) {
      case 't':
	{
	  unsigned char *out;

	  sscanf (buffer, "trigger %s %lu %lu %n", name, &type, &flags, &offset);
	  if ((trigger = trigger_find (name)))
	    trigger_delete (trigger);
	  out = string_unescape (buffer + offset);
	  trigger = trigger_create (name, type, out);
	  free (out);
	  break;
	}
      case 'r':
	sscanf (buffer, "rule %s %lu ", name, &type);
	trigger = trigger_find (name);
	if (!trigger)
	  break;
	switch (type) {
	  case TRIGGER_RULE_LOGIN:
	    sscanf (buffer, "rule %s %lu %lu %lu", name, &type, &cap, &flags);
	    rule = trigger_rule_create (trigger, TRIGGER_RULE_LOGIN, cap, flags, NULL, NULL);
	    break;
	  case TRIGGER_RULE_COMMAND:
	    sscanf (buffer, "rule %s %lu %lu %lu %s %n", name, &type, &cap, &flags, cmd, &offset);
	    rule =
	      trigger_rule_create (trigger, TRIGGER_RULE_COMMAND, cap, flags, cmd, buffer + offset);
	    break;
	  case TRIGGER_RULE_TIMER:
	    sscanf (buffer, "rule %s %lu %lu %lu %lu", name, &type, &cap, &flags, &interval);
	    rule =
	      trigger_rule_create (trigger, TRIGGER_RULE_TIMER, cap, flags, (void *) interval,
				   NULL);
	    break;
	}
	break;
      default:
	break;
    }
    fgets (buffer, sizeof (buffer), fp);
  }

  fclose (fp);

  return 0;
}

void trigger_clear ()
{
  while (ruleListCommand.next != &ruleListCommand)
    trigger_rule_delete (ruleListCommand.next);

  while (ruleListLogin.next != &ruleListLogin)
    trigger_rule_delete (ruleListLogin.next);

  while (ruleListTimer.next != &ruleListTimer)
    trigger_rule_delete (ruleListTimer.next);

  while (triggerList.next != &triggerList)
    trigger_delete (triggerList.next);
}

/************************************************************************************************/

unsigned long pi_trigger_handler_triggeradd (plugin_user_t * user, buffer_t * output, void *dummy,
					     unsigned int argc, unsigned char **argv)
{
  unsigned int type;
  trigger_t *t;

  if (argc < 4) {
    bf_printf (output, _("Usage: %s <name> <type> <arg>\n"
			 "   name: name of the trigger\n"
			 "   type: one of:\n"
			 "      - text : the trigger will dump the text provided in arg, \n"
			 "      - file : the trigger will dump the contents of the file provided in arg\n"
			 "	- command : the trigger will dump the output of the command provided in arg\n"
			 "   arg: depends on type\n"), argv[0]);
    return 0;
  }

  if (strlen (argv[1]) > TRIGGER_NAME_LENGTH) {
    bf_printf (output, _("Triggername %s is too long. Max %d characters\n"), argv[1],
	       TRIGGER_RELOAD_PERIOD);
    return 0;
  }

  if (trigger_find (argv[1])) {
    bf_printf (output, _("Triggername %s already exists."), argv[1]);
    return 0;
  }

  if (!strcmp (argv[2], "text")) {
    type = TRIGGER_TYPE_TEXT;
  } else if (!strcmp (argv[2], "file")) {
    type = TRIGGER_TYPE_FILE;
  } else if (!strcmp (argv[2], "command")) {
    type = TRIGGER_TYPE_COMMAND;
  } else {
    bf_printf (output, _("Unknown trigger type %s."), argv[2]);
    return 0;
  }

  t = trigger_create (argv[1], type, argv[3]);
  if (t) {
    bf_printf (output, _("Trigger %s created successfully."), argv[1]);
  } else {
    bf_printf (output, _("Trigger %s creation failed."), argv[1]);
  }
  return 0;
}

unsigned long pi_trigger_handler_triggerdel (plugin_user_t * user, buffer_t * output, void *dummy,
					     unsigned int argc, unsigned char **argv)
{
  trigger_t *t;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <name>\n" "   name: name of the trigger\n"), argv[0]);
    return 0;
  }


  if (!(t = trigger_find (argv[1]))) {
    bf_printf (output, _("Triggername %s doesn't exist."), argv[1]);
    return 0;
  }

  trigger_delete (t);
  bf_printf (output, _("Trigger %s deleted."), argv[1]);

  return 0;
}

unsigned int trigger_show (buffer_t * buf, trigger_t * trigger)
{
  switch (trigger->type) {
    case TRIGGER_TYPE_FILE:
      return bf_printf (buf, _("Trigger %s dumps file %s (Hits %ld)\n"),
			trigger->name, trigger->file, trigger->usecnt);
      break;
    case TRIGGER_TYPE_TEXT:
      return bf_printf (buf, _("Trigger %s dumps text %.*s (Hits %ld)\n"),
			trigger->name, bf_used (trigger->text), trigger->text->s, trigger->usecnt);
      break;
  };
  return 0;
}

unsigned long pi_trigger_handler_ruleadd (plugin_user_t * user, buffer_t * output, void *dummy,
					  unsigned int argc, unsigned char **argv)
{
  unsigned int type;
  trigger_t *t;
  trigger_rule_t *r;
  unsigned char *arg, *help;
  unsigned long long cap = 0, ncap = 0;
  unsigned long long capstart = 0, flags = 0, interval = 0;

  if (argc < 3)
    goto printhelp;

  if (!(t = trigger_find (argv[1]))) {
    bf_printf (output, _("Triggername %s doesn't exist."), argv[1]);
    return 0;
  }

  if (!strcasecmp (argv[2], "login")) {
    if (argc < 3)
      goto printhelp;
    type = TRIGGER_RULE_LOGIN;
    help = NULL;
    capstart = 3;
    arg = NULL;
  } else if (!strcasecmp (argv[2], "command")) {
    if (argc < 5)
      goto printhelp;
    type = TRIGGER_RULE_COMMAND;
    capstart = 5;
    help = argv[4];
    arg = argv[3];
  } else if (!strcasecmp (argv[2], "timer")) {
    if (argc < 4)
      goto printhelp;
    type = TRIGGER_RULE_TIMER;
    capstart = 4;
    help = NULL;
    interval = time_parse (argv[3]);
    if (!interval)
      goto printhelp;
    arg = (void *) interval;
  } else {
    bf_printf (output, _("Unknown trigger rule type %s."), argv[2]);
    return 0;
  }

  while (argv[capstart] && ((argv[capstart][0] == 'p') || (argv[capstart][0] == 'b'))) {
    if (!strcasecmp (argv[capstart], "pm")) {
      flags |= RULE_FLAG_PM;
      capstart++;
      continue;
    }
    if (!strcasecmp (argv[capstart], "broadcast")) {
      flags |= RULE_FLAG_BC;
      capstart++;
      continue;
    }
  }

  if (argv[capstart] && !strcasecmp (argv[capstart], "rights")) {
    capstart++;
    flags_parse (Capabilities, output, argc, argv, capstart, &cap, &ncap);
    cap &= ~ncap;
  }

  r = trigger_rule_create (t, type, cap, flags, arg, help);
  if (r) {
    bf_printf (output, _("Rule for trigger %s created successfully."), argv[1]);
  } else {
    bf_printf (output, _("Rule creation failed."));
  }

  return 0;

printhelp:
  bf_printf (output,
	     _("Usage: %s <name> <type> [<arg> [<help>]] [<pm>] [<broadcast>] [rights <cap>]\n"
	       "   name: name of the trigger\n" "   type: one of:\n"
	       "      - login   : the trigger will be triggered on user login, provide rights after type\n"
	       "      - command : the trigger will be triggered by a command, provide the command in <arg>,\n"
	       "                    then a help msg for the command, followed by any required rights\n"
	       "      - timer   : the trigger will be triggered every <arg> seconds (cannot be 0).\n"
	       "   arg: depends on type\n"
	       "   help: help message for command (only for command triggers)\n"
	       "   pm: always send trigger as a private message\n"
	       "   broadcast: send this to all users\n"
	       "   rights: rights required to activate rule\n"), argv[0]);
  return 0;
}

unsigned long pi_trigger_handler_ruledel (plugin_user_t * user, buffer_t * output, void *dummy,
					  unsigned int argc, unsigned char **argv)
{
  trigger_t *t;
  trigger_rule_t *r;
  unsigned long id;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <name> <id>\n"
			 "   name: name of the trigger\n" "   id  : ID of the rule\n"), argv[0]);
    return 0;
  }

  if (!(t = trigger_find (argv[1]))) {
    bf_printf (output, _("Triggername %s doesn't exist."), argv[1]);
    return 0;
  }

  sscanf (argv[2], "%lu", &id);

  if (!(r = trigger_rule_find (t, id))) {
    bf_printf (output, _("Trigger %s Rule ID %lu doesn't exist."), argv[1], id);
    return 0;
  }

  trigger_rule_delete (r);
  bf_printf (output, _("Trigger %s Rule ID %lu deleted."), argv[1], id);

  return 0;
}

unsigned int rule_show (buffer_t * buf, trigger_rule_t * rule)
{

  bf_printf (buf, _("  Rule %lu type "), rule->id);
  switch (rule->type) {
    case TRIGGER_RULE_COMMAND:
      bf_printf (buf, "command %s, ", rule->arg);
      break;

    case TRIGGER_RULE_LOGIN:
      bf_printf (buf, "login, ");
      break;

    case TRIGGER_RULE_TIMER:
      bf_printf (buf, "timer (%s), ", time_print (rule->interval));
      break;

    default:
      bf_printf (buf, "Unknown, ");
  }
  if (rule->flags & RULE_FLAG_PM)
    bf_printf (buf, "pm, ");
  if (rule->flags & RULE_FLAG_BC)
    bf_printf (buf, "broadcast, ");
  bf_printf (buf, " cap ");
  flags_print (Capabilities, buf, rule->cap);
  bf_strcat (buf, "\n");

  return bf_used (buf);
}

unsigned long pi_trigger_handler_rulelist (plugin_user_t * user, buffer_t * output, void *dummy,
					   unsigned int argc, unsigned char **argv)
{
  trigger_t *t;
  trigger_rule_t *r;
  unsigned int count, id;

  if (argc > 1) {
    count = 1;
    while ((count + 1) < argc) {
      t = trigger_find (argv[count]);
      if (!t) {
	bf_printf (output, _("Cannot find trigger %s\n"), argv[count]);
	count += 2;
	continue;
      }
      sscanf (argv[count + 1], "%u", &id);
      r = trigger_rule_find (t, id);
      if (!r) {
	bf_printf (output, _("Cannot find trigger %s rule ID %u\n"), argv[count], id);
	count += 2;
	continue;
      }
      trigger_show (output, t);
      rule_show (output, r);
      count += 2;
    }

    return 0;
  }

  for (t = triggerList.next; t != &triggerList; t = t->next) {
    trigger_show (output, t);

    for (r = ruleListLogin.next; r != &ruleListLogin; r = r->next)
      if (r->trigger == t)
	rule_show (output, r);

    for (r = ruleListCommand.next; r != &ruleListCommand; r = r->next)
      if (r->trigger == t)
	rule_show (output, r);

    for (r = ruleListTimer.next; r != &ruleListTimer; r = r->next)
      if (r->trigger == t)
	rule_show (output, r);
  };

  return 0;
}

unsigned long pi_trigger_event_save (plugin_user_t * user, void *dummy,
				     unsigned long event, void *arg)
{
  trigger_save (arg);
  return PLUGIN_RETVAL_CONTINUE;
}

unsigned long pi_trigger_event_load (plugin_user_t * user, void *dummy,
				     unsigned long event, void *arg)
{
  trigger_clear ();
  if (arg) {
    trigger_load (arg);
  } else {
    trigger_load_old (pi_trigger_SaveFile);
  }
  return PLUGIN_RETVAL_CONTINUE;
}

/************************************************************************************************/

/* init */
int pi_trigger_init ()
{

  pi_trigger_SaveFile = strdup ("trigger.conf");

  triggerList.next = &triggerList;
  triggerList.prev = &triggerList;
  ruleListCommand.next = &ruleListCommand;
  ruleListCommand.prev = &ruleListCommand;
  ruleListLogin.next = &ruleListLogin;
  ruleListLogin.prev = &ruleListLogin;
  ruleListTimer.next = &ruleListTimer;
  ruleListTimer.prev = &ruleListTimer;

  plugin_trigger = plugin_register ("trigger");
  plugin_request (plugin_trigger, PLUGIN_EVENT_LOGIN, &pi_trigger_login);
  plugin_request (plugin_trigger, PLUGIN_EVENT_CACHEFLUSH, &pi_trigger_timer);

  command_register ("triggeradd", &pi_trigger_handler_triggeradd, CAP_CONFIG, _("Add a trigger."));
  command_register ("triggerlist", &pi_trigger_handler_rulelist, CAP_CONFIG, _("List triggers."));
  command_register ("triggerdel", &pi_trigger_handler_triggerdel, CAP_CONFIG,
		    _("Delete a trigger."));

  command_register ("ruleadd", &pi_trigger_handler_ruleadd, CAP_CONFIG, _("Add a rule."));
  command_register ("ruledel", &pi_trigger_handler_ruledel, CAP_CONFIG, _("Delete a rule."));

  plugin_request (plugin_trigger, PLUGIN_EVENT_SAVE,
		  (plugin_event_handler_t *) & pi_trigger_event_save);
  plugin_request (plugin_trigger, PLUGIN_EVENT_LOAD,
		  (plugin_event_handler_t *) & pi_trigger_event_load);


  return 0;
}
