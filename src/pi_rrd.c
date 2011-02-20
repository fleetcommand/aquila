
#include <sys/stat.h>

#include "stats.h"
#include "etimer.h"
#include "utils.h"
#include "plugin.h"
#include "commands.h"
#include "aqtime.h"

#include "rrd.h"

typedef struct rrd_ctxt_datapoint {
  struct rrd_ctxt_datapoint *next, *prev;

  unsigned char *spec;
  value_element_t *elem;
} rrd_ctxt_datapoint_t;

typedef struct rrd_ctxt {
  struct rrd_ctxt *next, *prev;

  unsigned char *name;
  unsigned char *filename;
  unsigned long period;

  etimer_t timer;

  int npoints, nrras;
  rrd_ctxt_datapoint_t points;
  rrd_ctxt_datapoint_t rras;
} rrd_ctxt_t;

rrd_ctxt_t rrdlist;
unsigned long rrd_silent;

plugin_t *pi_rrd;

/*****************************************************************************/

int pi_rrd_update (rrd_ctxt_t * rrd)
{
  int retval;
  rrd_ctxt_datapoint_t *dp;
  unsigned int argc = 0;
  char *argv[4];
  buffer_t *u;

  u = bf_alloc ((rrd->npoints + rrd->nrras + 1) * 22);
  if (!u)
    goto error;

  bf_printf (u, "%lu:", now.tv_sec);

  for (dp = rrd->points.next; dp != &rrd->points; dp = dp->next) {
    switch (dp->elem->type) {
      case VAL_ELEM_LONG:
	bf_printf (u, "%ld:", *dp->elem->val.v_ulong);
	break;
      case VAL_ELEM_ULONG:
      case VAL_ELEM_MEMSIZE:
	bf_printf (u, "%lu:", *dp->elem->val.v_ulong);
	break;
      case VAL_ELEM_UINT:
	bf_printf (u, "%u:", *dp->elem->val.v_uint);
	break;
      case VAL_ELEM_INT:
	bf_printf (u, "%d:", *dp->elem->val.v_uint);
	break;
      case VAL_ELEM_BYTESIZE:
      case VAL_ELEM_ULONGLONG:
#ifdef USE_WINDOWS
	bf_printf (u, "%Lu:", *dp->elem->val.v_ulonglong);
#else
	bf_printf (u, "%I64u:", *dp->elem->val.v_ulonglong);
#endif
	break;
      case VAL_ELEM_DOUBLE:
	bf_printf (u, "%lf:", *dp->elem->val.v_uint);
	break;
      default:
	break;
    }
  }
  /* delete last colon */
  u->e[-1] = 0;

  argv[argc++] = "update";
  argv[argc++] = rrd->filename;
  argv[argc++] = u->s;
  argv[argc] = NULL;

  retval = rrd_update (argc, argv);
  if (retval < 0) {
    errno = 0;
    plugin_perror (_("RRD %s update failed: %s!"), rrd->name, rrd_get_error ());
  }

  bf_free (u);

error:
  /* set the timer for a multiple of the period */
  etimer_set (&rrd->timer, (rrd->period - (now.tv_sec % rrd->period)) * 1000);

  return retval;
}

int pi_rrd_start (rrd_ctxt_t * rrd)
{
  struct stat statbuf;

  /* if the file does not exist, we must create the RRD */
  if (stat (rrd->filename, &statbuf) < 0) {
    rrd_ctxt_datapoint_t *dp;
    unsigned int argc = 0;
    char *argv[256];
    unsigned char period[64];

    /* if ENOENT is returned, we need to create the archive file */
    if (errno != ENOENT)
      return -1;

    argv[argc++] = "create";
    argv[argc++] = rrd->filename;

    /* we add the argument to set a non-standard step */
    if (rrd->period != 300) {
      snprintf (period, 64, "%lu", rrd->period);
      argv[argc++] = "-s";
      argv[argc++] = period;
    }


    /* we add the data points */
    for (dp = rrd->points.next; (dp != &rrd->points) && (argc < 255); dp = dp->next)
      argv[argc++] = dp->spec;

    /* we add the RRAs */
    for (dp = rrd->rras.next; (dp != &rrd->rras) && (argc < 255); dp = dp->next)
      argv[argc++] = dp->spec;

    argv[argc] = NULL;

    /* create the rrd! */
    errno = 0;
    if (rrd_create (argc, argv) < 0)
      return -1;
  }

  /* init the timer */
  etimer_init (&rrd->timer, (etimer_handler_t *) pi_rrd_update, rrd);

  /* set the timer for a multiple of the period */
  etimer_set (&rrd->timer, (rrd->period - (now.tv_sec % rrd->period)) * 1000);

  return 0;
}

rrd_ctxt_datapoint_t *pi_rrd_datapoint_create (buffer_t * output, rrd_ctxt_datapoint_t * list,
					       unsigned char *name, unsigned char *spec)
{
  rrd_ctxt_datapoint_t *dp;
  value_element_t *elem = NULL;

  if (name) {
    elem = stats_find (name);
    if (!elem) {
      if (output)
	bf_printf (output, _("Statistic %s not found.\n"), name);
      return NULL;
    }
  }

  dp = malloc (sizeof (rrd_ctxt_datapoint_t));
  if (!dp)
    return NULL;

  memset (dp, 0, sizeof (rrd_ctxt_datapoint_t));
  dp->elem = elem;
  dp->spec = strdup (spec);

  dp->next = list;
  dp->prev = list->prev;
  dp->next->prev = dp;
  dp->prev->next = dp;

  return dp;
}

void pi_rrd_datapoint_clear (rrd_ctxt_t * rrd)
{
  rrd_ctxt_datapoint_t *dp;

  for (dp = rrd->points.next; dp != &rrd->points; dp = rrd->points.next) {
    dp->next->prev = dp->prev;
    dp->prev->next = dp->next;
    free (dp->spec);
    free (dp);
  }
  for (dp = rrd->rras.next; dp != &rrd->rras; dp = rrd->rras.next) {
    dp->next->prev = dp->prev;
    dp->prev->next = dp->next;
    free (dp->spec);
    free (dp);
  }
}

rrd_ctxt_t *pi_rrd_create (unsigned char *name, unsigned char *filename, unsigned long period)
{
  rrd_ctxt_t *rrd;

  rrd = malloc (sizeof (rrd_ctxt_t));
  if (!rrd)
    return NULL;

  memset (rrd, 0, sizeof (rrd_ctxt_t));
  rrd->name = strdup (name);
  rrd->filename = strdup (filename);
  rrd->period = period;

  rrd->points.next = &rrd->points;
  rrd->points.prev = &rrd->points;
  rrd->rras.next = &rrd->rras;
  rrd->rras.prev = &rrd->rras;

  rrd->next = &rrdlist;
  rrd->prev = rrdlist.prev;
  rrd->next->prev = rrd;
  rrd->prev->next = rrd;

  return rrd;
}

void pi_rrd_delete (rrd_ctxt_t * rrd)
{
  etimer_cancel (&rrd->timer);

  pi_rrd_datapoint_clear (rrd);

  rrd->next->prev = rrd->prev;
  rrd->prev->next = rrd->next;

  free (rrd->name);
  free (rrd->filename);
  free (rrd);
}

rrd_ctxt_t *pi_rrd_find (unsigned char *name)
{
  rrd_ctxt_t *rrd;

  for (rrd = rrdlist.next; rrd != &rrdlist; rrd = rrd->next)
    if (!strcmp (rrd->name, name))
      return rrd;

  return NULL;
}

int pi_rrd_save (xml_node_t * base)
{
  xml_node_t *node;
  rrd_ctxt_t *rrd;
  rrd_ctxt_datapoint_t *dp;

  base = xml_node_add (base, "RRDs");

  for (rrd = rrdlist.next; rrd != &rrdlist; rrd = rrd->next) {
    node = xml_node_add (base, "RRD");
    xml_node_add_value (node, "Name", XML_TYPE_STRING, rrd->name);
    xml_node_add_value (node, "File", XML_TYPE_STRING, rrd->filename);
    xml_node_add_value (node, "Period", XML_TYPE_ULONG, &rrd->period);

    node = xml_node_add (node, "DataPoints");
    for (dp = rrd->points.next; dp != &rrd->points; dp = dp->next) {
      node = xml_node_add (node, "DataPoint");
      xml_node_add_value (node, "Name", XML_TYPE_STRING, dp->elem->name);
      xml_node_add_value (node, "Specification", XML_TYPE_STRING, dp->spec);
      node = xml_parent (node);
    }
    node = xml_parent (node);

    node = xml_node_add (node, "RRAs");
    for (dp = rrd->rras.next; dp != &rrd->rras; dp = dp->next)
      xml_node_add_value (node, "RRA", XML_TYPE_STRING, dp->spec);
    node = xml_parent (node);
  }
  return 0;
}

int pi_rrd_load (xml_node_t * base)
{
  xml_node_t *node;
  rrd_ctxt_t *rrd;
  unsigned char *name = NULL, *file = NULL, *dp = NULL, *spec = NULL;
  unsigned long period;

  base = xml_node_find (base, "RRDs");
  if (!base)
    return PLUGIN_RETVAL_CONTINUE;

  for (rrd = rrdlist.next; rrd != &rrdlist; rrd = rrdlist.next)
    pi_rrd_delete (rrd);

  for (node = base->children; node; node = xml_next (node)) {
    if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
      continue;
    if (!xml_child_get (node, "File", XML_TYPE_STRING, &file))
      continue;
    if (!xml_child_get (node, "Period", XML_TYPE_ULONG, &period))
      continue;


    rrd = pi_rrd_create (name, file, period);
    if (!rrd)
      continue;

    base = node;
    node = xml_node_find (base, "DataPoints");
    for (node = node->children; node; node = xml_next (node)) {
      if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
	continue;
      if (!xml_child_get (node, "Specification", XML_TYPE_STRING, &spec))
	continue;

      rrd->npoints++;
      pi_rrd_datapoint_create (NULL, &rrd->points, name, spec);
    }

    node = xml_node_find (base, "RRAs");
    for (node = node->children; node; node = xml_next (node)) {
      pi_rrd_datapoint_create (NULL, &rrd->rras, NULL, node->value);
      rrd->nrras++;
    }

    node = base;

    pi_rrd_start (rrd);
  }

  if (name)
    free (name);
  if (file)
    free (file);
  if (dp)
    free (dp);
  if (spec)
    free (spec);

  return PLUGIN_RETVAL_CONTINUE;
}

/*****************************************************************************/
unsigned long pi_rrd_handler_rrdcreate (plugin_user_t * user, buffer_t * output, void *dummy,
					unsigned int argc, unsigned char **argv)
{
  rrd_ctxt_t *rrd = NULL;
  unsigned long period, i;
  unsigned char *ds = NULL, *s, *e;


  if (argc < 4) {
    bf_printf (output, _("Usage: %s <name> <filename> <period>\n"
			 "          [DS:ds-name:DST:dst arguments]\n"
			 "          [RRA:CF:cf arguments]\n"
			 " <name>: name of the rrd entry\n"
			 " <filename>: filename to save data in\n"
			 " <period>: how often to sample data (suggestion: 300s)\n"
			 "  for the other arguments please consult the rrdtool manual\n"), argv[0]);
    return 0;
  }

  rrd = pi_rrd_find (argv[1]);
  if (rrd) {
    bf_printf (output, _("RRD %s already exists."), argv[1]);
    return 0;
  }

  period = time_parse (argv[3]);
  if (!period) {
    bf_printf (output, _("%s: %s is not a valid time string\n"), argv[0], argv[3]);
    return 0;
  }

  rrd = pi_rrd_create (argv[1], argv[2], period);
  if (!rrd)
    return 0;

  for (i = 4; i < argc; i++) {
    if (!strncmp (argv[i], "DS", 2)) {
      ds = strdup (argv[i]);
      if (!ds)
	goto error;
      /* extract stat name */
      s = strchr (ds, ':');
      e = NULL;
      if (s)
	e = strchr (s + 1, ':');
      if (!s || !e) {
	bf_printf (output, _("DS entry has bad format: %s\n"), ds);
	free (ds);
	goto error;
      }
      s++;
      *e = 0;

      /* replace all . with _ */
      e = strchr (argv[i], ':');
      for (e++; *e != ':'; e++)
	if (*e == '.')
	  *e = '_';

      /* create DS */
      pi_rrd_datapoint_create (output, &rrd->points, s, argv[i]);
      free (ds);
      rrd->npoints++;
    } else if (!strncmp (argv[i], "RRA", 3)) {
      pi_rrd_datapoint_create (output, &rrd->rras, NULL, argv[i]);
      rrd->nrras++;
    } else
      continue;

  }

  if (pi_rrd_start (rrd)) {
    bf_printf (output, _("RRD create FAILED: %s\n"), rrd_get_error ());
    goto error;
  }

  bf_printf (output, _("RRD %s created.\n"), rrd->name);

  return 0;

error:
  if (rrd)
    pi_rrd_delete (rrd);

  return 0;
}

unsigned long pi_rrd_handler_rrdlist (plugin_user_t * user, buffer_t * output, void *dummy,
				      unsigned int argc, unsigned char **argv)
{
  rrd_ctxt_t *rrd;
  rrd_ctxt_datapoint_t *dp;

  bf_printf (output, "\n");
  for (rrd = rrdlist.next; rrd != &rrdlist; rrd = rrd->next) {
    bf_printf (output, _("RRD %s filename: %s period: %lu\n"), rrd->name, rrd->filename,
	       rrd->period);
    for (dp = rrd->points.next; dp != &rrd->points; dp = dp->next)
      bf_printf (output, "  %s (%s)\n", dp->spec, dp->elem->name);
    for (dp = rrd->rras.next; dp != &rrd->rras; dp = dp->next)
      bf_printf (output, "  %s\n", dp->spec);
    bf_printf (output, "\n");
  }

  return 0;
}

unsigned long pi_rrd_handler_rrddelete (plugin_user_t * user, buffer_t * output, void *dummy,
					unsigned int argc, unsigned char **argv)
{
  rrd_ctxt_t *rrd;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <name>\n"), argv[0]);
    return 0;
  }

  rrd = pi_rrd_find (argv[1]);
  if (!rrd) {
    bf_printf (output, _("RRD %s not found.\n"), argv[1]);
    return 0;
  }

  pi_rrd_delete (rrd);
  bf_printf (output, _("RRD %s deleted.\n"), argv[1]);

  return 0;
}

unsigned long pi_rrd_handle_save (plugin_user_t * user, void *ctxt, unsigned long event,
				  void *token)
{
  return token ? pi_rrd_save (token) : PLUGIN_RETVAL_CONTINUE;
}

unsigned long pi_rrd_handle_load (plugin_user_t * user, void *ctxt, unsigned long event,
				  void *token)
{
  return token ? pi_rrd_load (token) : PLUGIN_RETVAL_CONTINUE;
}

/*****************************************************************************/

int pi_rrd_init ()
{
  pi_rrd = plugin_register ("rrd");

  /* *INDENT-OFF* */
  command_register ("rrdcreate", &pi_rrd_handler_rrdcreate, CAP_CONFIG, _("Create an RRD file for statistics gathering"));
  command_register ("rrdlist",   &pi_rrd_handler_rrdlist,   CAP_CONFIG, _("Show the RRD file generated."));
  command_register ("rrddelete", &pi_rrd_handler_rrddelete,   CAP_CONFIG, _("Remove a RRD file."));
  /* *INDENT-ON* */

  plugin_request (NULL, PLUGIN_EVENT_LOAD, (plugin_event_handler_t *) pi_rrd_handle_load);
  plugin_request (NULL, PLUGIN_EVENT_SAVE, (plugin_event_handler_t *) pi_rrd_handle_save);

  config_register ("rrd.silent", CFG_ELEM_ULONG, &rrd_silent,
		   _("If set, errors are not reported."));


  rrdlist.next = &rrdlist;
  rrdlist.prev = &rrdlist;

  return 0;
}
