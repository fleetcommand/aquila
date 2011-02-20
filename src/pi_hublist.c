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
 *  Thanks to Tomas "ZeXx86" Jedrzejek (admin@infern0.tk) for example code.
 */

#include "esocket.h"
#include "etimer.h"

#include <unistd.h>
#include <string.h>

#include "aqtime.h"
#include "buffer.h"
#include "config.h"
#include "commands.h"
#include "plugin.h"

#include "../config.h"

#ifndef __USE_W32_SOCKETS
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#ifdef USE_WINDOWS
#  include "sys_windows.h"
#endif

#define PI_HUBLIST_BUFFER_SIZE 	4096
#define PI_HUBLIST_TIMEOUT 10000


#define PI_HUBLIST_FLAGS_REPORT    1


typedef struct pi_hublist_ctx {
  unsigned char *address;
  unsigned long flags;
  etimer_t timer;
} pi_hublist_ctx_t;

unsigned char *pi_hublist_lists;

struct timeval pi_hublist_savetime;
unsigned long pi_hublist_interval;
unsigned long pi_hublist_silent;

unsigned int pi_hublist_es_type;
esocket_handler_t *pi_hublist_handler;

extern long users_total;

plugin_t *pi_hublist;

int pi_hublist_handle_timeout (esocket_t * s);

static int escape_string (buffer_t * output)
{
  int i, j;
  unsigned char *l, *e;
  buffer_t *tmpbuf;

  tmpbuf = bf_copy (output, 0);

  l = tmpbuf->s;
  e = output->buffer + output->size - 10;
  j = bf_used (tmpbuf);
  bf_clear (output);

  /* do not escape first $ character */
  if (*l == '$') {
    l++;
    output->e++;
    j--;
  };

  for (i = 0; (i < j) && (output->e < e); i++)
    switch (l[i]) {
      case 0:
      case 5:
      case 36:
      case 96:
      case 124:
      case 126:
	bf_printf (output, "/%%DCN%03d%%/", l[i]);
	break;
      default:
	if (bf_unused (output) > 0)
	  *output->e++ = l[i];
    }

  if (bf_unused (output) > 0)
    *output->e = '\0';

  bf_free (tmpbuf);

  return bf_used (output);
}


int pi_hublist_update (buffer_t * output, unsigned long flags)
{
  int result;
  unsigned int port;
  unsigned char *lists, *l, *p;
  esocket_t *s;
  pi_hublist_ctx_t *ctx;

  if (!pi_hublist_lists || !*pi_hublist_lists) {
    bf_printf (output, _("No hublists configured\n"));
    return 0;
  }

  lists = strdup (pi_hublist_lists);

  for (l = strtok (lists, ";, "); l; l = strtok (NULL, ";, ")) {
    if (!strlen (l))
      continue;

    ctx = malloc (sizeof (pi_hublist_ctx_t));
    memset (ctx, 0, sizeof (pi_hublist_ctx_t));
    ctx->address = strdup (l);
    ctx->flags = flags;

    DPRINTF ("pi_hublist: hublist Registering at %s\n", l);
    /* extract port */
    p = strchr (l, ':');
    if (p) {
      port = atoi (p + 1);
      *p = '\0';
    } else
      port = 2501;

    /* create esocket */
    s =
      esocket_new (pi_hublist_handler, pi_hublist_es_type, AF_INET, SOCK_STREAM, 0,
		   (uintptr_t) ctx);

    if (!s) {
      bf_printf (output, _("Hublist update ERROR: %s: socket: %s\n"), l, strerror (errno));
      DPRINTF ("pi_hublist: socket: %.*s", (int) bf_used (output), output->s);
      free (ctx->address);
      free (ctx);
      continue;
    }

    /* connect */
    if ((result = esocket_connect (s, l, port)) != 0) {
      if (result > 0) {
	bf_printf (output, _("Hublist update ERROR: %s: connect: %s\n"), l, gai_strerror (result));
	DPRINTF ("pi_hublist: connect: %.*s", (int) bf_used (output), output->s);
      } else {
	bf_printf (output, _("Hublist update ERROR: %s: connect: %s\n"), l, strerror (-result));
	DPRINTF ("pi_hublist: connect: %.*s", (int) bf_used (output), output->s);
      }
      esocket_close (s);
      free (ctx->address);
      free (ctx);
      esocket_remove_socket (s);
      continue;
    };

    etimer_init (&ctx->timer, (etimer_handler_t *) pi_hublist_handle_timeout, s);
    etimer_set (&ctx->timer, PI_HUBLIST_TIMEOUT);
  };

  free (lists);
  return 0;
};

int pi_hublist_handle_input (esocket_t * s)
{
  int n;
  unsigned int i, j, port;
  buffer_t *buf, *output;
  struct sockaddr_in local;
  char *t, *l, *k;
  config_element_t *hubname, *hostname, *listenport, *hubdesc;
  pi_hublist_ctx_t *ctx = (pi_hublist_ctx_t *) s->context;

  buf = bf_alloc (PI_HUBLIST_BUFFER_SIZE);
  output = NULL;

  /* read data */
  n = esocket_recv (s, buf);
  if (n <= 0) {
    bf_clear (buf);
    bf_printf (buf, _("Hublist update ERROR: %s: read: %s\n"), ctx->address, strerror (errno));
    DPRINTF ("pi_hublist: read: %.*s", (int) bf_used (buf), buf->s);
    if ((!pi_hublist_silent) || (ctx->flags & PI_HUBLIST_FLAGS_REPORT))
      plugin_report (buf);
    goto leave;
  }
  *(buf->e - 1) = '\0';

  /* retrieve remote port */
  n = sizeof (local);
  if (getsockname (s->socket, (struct sockaddr *) &local, &n)) {
    bf_clear (buf);
    bf_printf (buf, _("Hublist update ERROR: %s: getsockname: %s\n"), ctx->address,
	       strerror (errno));
    DPRINTF ("pi_hublist: getsockname: %.*s", (int) bf_used (buf), buf->s);
    if ((!pi_hublist_silent) || (ctx->flags & PI_HUBLIST_FLAGS_REPORT))
      plugin_report (buf);
    goto leave;
  }
  port = ntohs (local.sin_port);

  output = bf_alloc (PI_HUBLIST_BUFFER_SIZE);

  /* extract lock */
  t = buf->s + 6;		/* skip '$Lock ' */
  l = strsep (&t, " ");
  j = t - l - 1;

  /* verify pointers */
  if (!t || (j >= PI_HUBLIST_BUFFER_SIZE)) {
    if ((!pi_hublist_silent) || (ctx->flags & PI_HUBLIST_FLAGS_REPORT)) {
      bf_clear (output);
      bf_printf (output, _("Hublist update ERROR: %s: illegal input %.*s\n"), (int) bf_used (buf),
		 buf->s);
      plugin_report (output);
    }
    goto leave;
  }

  /* prepare output buffer */
  bf_strcat (output, "$Key ");
  k = output->e;

  /* calculate key */
  for (i = 1; i < j; i++)
    k[i] = l[i] ^ l[i - 1];

  /* use port as magic byte */
  k[0] = l[0] ^ k[j - 1] ^ ((port + (port >> 8)) & 0xff);

  for (i = 0; i < j; i++)
    k[i] = ((k[i] << 4) & 240) | ((k[i] >> 4) & 15);

  k[j] = '\0';

  output->e += j;

  /* escape key */
  escape_string (output);

  bf_strcat (output, "|");

  hubname = config_find ("hubname");
  ASSERT (hubname);
  hostname = config_find ("hubaddress");
  ASSERT (hostname);
  listenport = config_find ("nmdc.listenport");
  ASSERT (listenport);
  hubdesc = config_find ("hubdescription");
  ASSERT (hubdesc);
#ifndef USE_WINDOWS
  bf_printf (output, "%s|%s:%u|%s|%d|%llu|",
	     *hubname->val.v_string ? *hubname->val.v_string : (unsigned char *) "",
	     *hostname->val.v_string ? *hostname->val.v_string : (unsigned char *) "",
	     *listenport->val.v_uint ? *listenport->val.v_uint : 411,
	     *hubdesc->val.v_string ? *hubdesc->val.v_string : (unsigned char *) "",
#ifdef PLUGIN_USER
	     users_total,
#else
	     0,
#endif
	     0LL);
#else
  bf_printf (output, "%s|%s:%u|%s|%d|%I64u|",
	     *hubname->val.v_string ? *hubname->val.v_string : (unsigned char *) "",
	     *hostname->val.v_string ? *hostname->val.v_string : (unsigned char *) "",
	     *listenport->val.v_uint ? *listenport->val.v_uint : 411,
	     *hubdesc->val.v_string ? *hubdesc->val.v_string : (unsigned char *) "",
#ifdef PLUGIN_USER
	     users_total,
#else
	     0,
#endif
	     0LL);

#endif
  DPRINTF ("pi_hublist:  Send: %.*s\n", (int) bf_used (output), output->s);

  n = esocket_send (s, output, 0);
  if (n < 0) {
    bf_clear (buf);
    bf_printf (buf, _("Hublist update ERROR: %s: send: %s\n"), ctx->address, strerror (errno));
    if ((!pi_hublist_silent) || (ctx->flags & PI_HUBLIST_FLAGS_REPORT))
      plugin_report (buf);
    DPRINTF ("pi_hublist: esocket_send: %.*s", (int) bf_used (buf), buf->s);
  }

  if (ctx->flags & PI_HUBLIST_FLAGS_REPORT) {
    bf_clear (buf);
    bf_printf (buf, _("Registered at hublist %s\n"), ctx->address);
    plugin_report (buf);
  }
#ifdef DEBUG
  DPRINTF ("pi_hublist:  -- Registered at hublist %s\n", ctx->address);
#endif

leave:
  if (output)
    bf_free (output);
  bf_free (buf);

  free (ctx->address);
  free (ctx);
  etimer_cancel (&ctx->timer);
  esocket_close (s);
  esocket_remove_socket (s);

  return 0;
};

int pi_hublist_handle_error (esocket_t * s)
{
  buffer_t *buf;
  pi_hublist_ctx_t *ctx = (pi_hublist_ctx_t *) s->context;

  if (s->state == SOCKSTATE_FREED)
    return 0;

  /* we are connected, just wait for input */
  if (!s->error) {
    etimer_set (&ctx->timer, PI_HUBLIST_TIMEOUT);
    return 0;
  }

  /* an error occured */
  buf = bf_alloc (10240);

  bf_printf (buf, _("Hublist update ERROR: %s: %s.\n"), ctx->address, strerror (s->error));
  if ((!pi_hublist_silent) || (ctx->flags & PI_HUBLIST_FLAGS_REPORT))
    plugin_report (buf);
  DPRINTF ("pi_hublist: error: %.*s", (int) bf_used (buf), buf->s);

  etimer_cancel (&ctx->timer);
  free (ctx->address);
  free (ctx);
  esocket_close (s);
  esocket_remove_socket (s);

  bf_free (buf);

  return 0;
};

int pi_hublist_handle_timeout (esocket_t * s)
{
  buffer_t *buf;
  pi_hublist_ctx_t *ctx = (pi_hublist_ctx_t *) s->context;

  if (s->state == SOCKSTATE_FREED)
    return 0;

  if (s->state == SOCKSTATE_RESOLVING) {
    etimer_set (&ctx->timer, PI_HUBLIST_TIMEOUT);
    return 0;
  }

  buf = bf_alloc (10240);

  bf_printf (buf, _("Hublist update ERROR: %s: Timed out.\n"), ctx->address);
  if ((!pi_hublist_silent) || (ctx->flags & PI_HUBLIST_FLAGS_REPORT))
    plugin_report (buf);
  DPRINTF ("pi_hublist: timeout: %.*s", (int) bf_used (buf), buf->s);

  free (ctx->address);
  free (ctx);
  esocket_close (s);
  esocket_remove_socket (s);

  bf_free (buf);

  return 0;
};


unsigned long pi_hublist_handle_update (plugin_user_t * user, void *ctxt, unsigned long event,
					void *token)
{
  buffer_t *output;
  unsigned int l;

  if (!pi_hublist_interval)
    return 0;

  if (now.tv_sec > (pi_hublist_savetime.tv_sec + (time_t) pi_hublist_interval)) {
    pi_hublist_savetime = now;
    output = bf_alloc (1024);
    bf_printf (output, _("Errors during hublist update:\n"));
    l = bf_used (output);

    pi_hublist_update (output, 0);

    if ((bf_used (output) != l) && (!pi_hublist_silent)) {
      plugin_report (output);
    }
    bf_free (output);
  }

  return 0;
}

unsigned long pi_hublist_handler_hublist (plugin_user_t * user, buffer_t * output, void *dummy,
					  unsigned int argc, unsigned char **argv)
{
  gettimeofday (&pi_hublist_savetime, NULL);

  pi_hublist_update (output, PI_HUBLIST_FLAGS_REPORT);

  return 0;
}

int pi_hublist_setup (esocket_handler_t * h)
{
  pi_hublist_es_type =
    esocket_add_type (h, ESOCKET_EVENT_IN, pi_hublist_handle_input, NULL, pi_hublist_handle_error);

  plugin_request (NULL, PLUGIN_EVENT_CACHEFLUSH,
		  (plugin_event_handler_t *) pi_hublist_handle_update);

  pi_hublist_handler = h;

  return 0;
}

int pi_hublist_init ()
{
  pi_hublist_es_type = -1;

  pi_hublist = plugin_register ("hublist");

  gettimeofday (&pi_hublist_savetime, NULL);

  pi_hublist_interval = 0;
  pi_hublist_silent = 0;
  pi_hublist_lists = strdup ("");

  config_register ("hublist.lists", CFG_ELEM_STRING, &pi_hublist_lists,
		   _("list of hublist addresses."));
  config_register ("hublist.interval", CFG_ELEM_ULONG, &pi_hublist_interval,
		   _("Interval of hublist updates."));
  config_register ("hublist.silent", CFG_ELEM_ULONG, &pi_hublist_silent,
		   _("Do not report errors when hublist registration fails (Use with caution!)."));

  command_register ("hublist", &pi_hublist_handler_hublist, CAP_CONFIG, _("Register at hublists."));

  return 0;
};
