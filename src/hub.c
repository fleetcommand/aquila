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

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <string.h>

#include "../config.h"
#ifndef __USE_W32_SOCKETS
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#  ifdef HAVE_NETINET_TCP_H
#    include <netinet/tcp.h>
#  endif
#else
#  define SHUT_RDWR	SD_BOTH
#  define close(x) closesocket(x)
#endif

#if 0
#define BUF_DPRINTF(x...) DPRINTF(x)
#else
#define BUF_DPRINTF(x...)	/* x */
#endif

#include "core_config.h"
#include "iplist.h"
#include "aqtime.h"

#define HUB_INPUTBUFFER_SIZE	4096

/* local hub cache */

/* global redir stats */
unsigned long buffering = 0;
unsigned long buf_mem = 0;

unsigned int ndelay = 1;
unsigned int blockonoverflow = 1;
unsigned int disconnectontimeout = 1;

/* banlist */
banlist_t hardbanlist, softbanlist;

iplist_t lastlist;

unsigned int es_type_server, es_type_listen;

hub_statistics_t hubstats;

int server_disconnect_user (client_t *, char *);

/*****************************************************************************
**                         INTERNAL HANDLERS                                **
*****************************************************************************/

int server_handle_timeout (client_t * cl)
{
  esocket_t *s = cl->es;

  ASSERT (s->state != SOCKSTATE_FREED);
  if (s->state == SOCKSTATE_FREED)
    return 0;

  if (!disconnectontimeout)
    return 0;

  DPRINTF ("Buffering timeout user %s : %d\n", cl->user->nick, cl->user->state);
  return server_disconnect_user (cl, __ ("Buffering Timeout"));
}

__inline__ int server_settimer (client_t * cl, unsigned long timeout)
{
  if (!cl->timer && timeout)
    cl->timer = etimer_alloc ((etimer_handler_t *) server_handle_timeout, (void *) cl);

  return timeout ? etimer_set (cl->timer, timeout) : etimer_cancel (cl->timer);
}


/****************************** DATA SOCKETS *********************************/

int server_handle_output (esocket_t * es)
{
  client_t *cl = (client_t *) es->context;
  buffer_t *b;
  long w;
  unsigned long t, l, o;
  string_list_entry_t *e;

  /* duplicate event */
  if (!cl->outgoing.count)
    return 0;

  BUF_DPRINTF (" %p Writing output (%u, %lu)...", cl->user, cl->outgoing.count, cl->offset);
  w = 0;
  t = 0;
  b = NULL;

  buf_mem -= cl->outgoing.size;

  /* write out as much data as possible */
  o = cl->offset;
  for (e = cl->outgoing.first; e; e = cl->outgoing.first) {
    b = e->data;
    /* skip buffers we wrote already */
    while (b && (bf_used (b) < o)) {
      o -= bf_used (b);
      b = b->next;
    }
    ASSERT (b);
    /* write out data in buffer chain */
    for (; b; b = b->next) {
      l = bf_used (b) - o;
      w = esocket_send (es, b, o);
      if (w < 0) {
	switch (errno) {
	  case EAGAIN:
	  case ENOMEM:
	    break;
	  case EPIPE:
#ifndef USE_WINDOWS
	  case ECONNRESET:
#endif
	    buf_mem += cl->outgoing.size;
	    server_disconnect_user (cl, __ ("Connection closed."));
	    return -1;
	  default:
	    buf_mem += cl->outgoing.size;
	    return -1;
	}
	w = 0;
	break;
      }
      t += w;
      cl->offset += w;
      hubstats.TotalBytesSend += w;
      if ((unsigned) w != l)
	break;
      o = 0;
    }
    if (b)
      break;

    /* prepare for next buffer */
    cl->offset = 0;
    string_list_del (&cl->outgoing, e);
  }
  if (cl->credit) {
    if (cl->credit > t) {
      cl->credit -= t;
    } else {
      cl->credit = 0;
    };
  }
  STRINGLIST_VERIFY (&cl->outgoing);

  /* still not all data written */
  if (b) {
    if ((cl->state == HUB_STATE_OVERFLOW)
	&& ((cl->outgoing.size - cl->offset) < (config.BufferSoftLimit + cl->credit))) {
      server_settimer (cl, config.TimeoutBuffering);
      cl->state = HUB_STATE_BUFFERING;
    }

    buf_mem += cl->outgoing.size;

    BUF_DPRINTF (" wrote %lu, still %u buffers, size %lu (offset %lu, credit %lu)\n", t,
		 cl->outgoing.count, cl->outgoing.size, cl->offset, cl->credit);
    return 0;
  }

  BUF_DPRINTF (" wrote %lu, ALL CLEAR (%u, %lu)!!\n", t, cl->outgoing.count, cl->offset);

  /* all data was written, we don't need the output event anymore */
  ASSERT (!cl->outgoing.count);

  esocket_clearevents (cl->es, ESOCKET_EVENT_OUT);
  server_settimer (cl, 0);
  buffering--;
  cl->state = HUB_STATE_NORMAL;

  return 0;
}

int server_handle_input (esocket_t * s)
{
  client_t *cl = (client_t *) s->context;
  buffer_t *b;
  int n, first;

  ASSERT (cl->es == s);

  /* read available data */
  first = 1;
  for (;;) {
    /* alloc new buffer and read data in it. break loop if no data available */
    b = bf_alloc (HUB_INPUTBUFFER_SIZE);
    if (!b)
      return -1;

    n = recv (s->socket, b->s, HUB_INPUTBUFFER_SIZE, 0);
    if (n <= 0)
      break;

    hubstats.TotalBytesReceived += n;
    first = 0;
    /* init buffer and store */
    b->e = b->s + n;
    bf_append (&cl->buffers, b);

    if (n < HUB_INPUTBUFFER_SIZE)
      break;
  };
  if (n <= 0) {
    bf_free (b);
    b = NULL;
  }

  if ((n <= 0) && first) {
#ifdef USE_WINDOWS
    if (WSAGetLastError () == WSAEWOULDBLOCK)
      return 0;
#else
    if (errno == EAGAIN)
      return 0;
#endif
    server_disconnect_user (cl, __ ("Error on read."));
    return -1;
  }

  if (blockonoverflow && (cl->state == HUB_STATE_OVERFLOW)) {
    bf_free (cl->buffers);
    cl->buffers = NULL;
    cl->proto->handle_input (cl->user, NULL);
    return 0;
  }

  gettime ();
  if (cl->buffers)
    cl->proto->handle_input (cl->user, &cl->buffers);

  return 0;
}

int server_error (esocket_t * s)
{
  char buffer[256];
  client_t *cl = (client_t *) ((uintptr_t) s->context);

  if (!cl)
    return 0;

  ASSERT (s->state != SOCKSTATE_FREED);
  if (s->state == SOCKSTATE_FREED)
    return 0;


  DPRINTF ("Error on user %s : %d\n", cl->user->nick, cl->user->state);

  if (s->error) {
    sprintf (buffer, __ ("Socket error %d."), s->error);
  } else {
    sprintf (buffer, __ ("Socket errno %d."), errno);
  }

  return server_disconnect_user (cl, buffer);
}

/**************************** LISTENING SOCKETS ******************************/

int accept_new_user (esocket_t * s)
{
  int l = 0;
  char buffer[1024];

#ifndef USE_WINDOWS
  int r, yes = 1;
#else
  SOCKET r;
#endif
  struct sockaddr_in client_address;
  client_t *cl = NULL;

  gettime ();
#ifndef USE_WINDOWS
  for (;;)
#endif
  {
    l = sizeof (client_address);
    memset (&client_address, 0, l);
    r = esocket_accept (s, (struct sockaddr *) &client_address, &l);

    if (r == INVALID_SOCKET) {
      if (errno == EAGAIN)
	return 0;
      perror ("accept:");
      return -1;
    }
    l = 0;

#ifndef USE_WINDOWS
    if (ndelay) {
      if (setsockopt (r, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof (yes)) < 0) {
	DPRINTF ("setsockopt (TCP_NODELAY): %s\n", strerror (errno));
	shutdown (r, SHUT_RDWR);
	close (r);
	return -1;
      }
    }
#endif

    /* before all else, test hardban */
    if (banlist_find_byip (&hardbanlist, client_address.sin_addr.s_addr)) {
      shutdown (r, SHUT_RDWR);
      close (r);
      return -1;
    }

    /* make socket non-blocking */
#ifndef USE_IOCP
    if (fcntl (r, F_SETFL, O_NONBLOCK)) {
      perror ("ioctl(O_NONBLOCK):");
      close (r);
      return -1;
    };
#else
    {
      DWORD yes = 1;
      DWORD bytes = 0;

      if (WSAIoctl (r, FIONBIO, &yes, sizeof (yes), NULL, 0, &bytes, NULL, NULL)) {
	perror ("WSAIoctl (FIONBIO):");
	close (r);
	return -1;
      }
    }
#endif

    /* check last connection list */
    if (iplist_interval) {
      if (iplist_find (&lastlist, client_address.sin_addr.s_addr)) {
	l = snprintf (buffer, sizeof (buffer), __ ("<%s> Don't reconnect so fast.|"), HUBSOFT_NAME);
	goto error;
      }
      iplist_add (&lastlist, client_address.sin_addr.s_addr);
    }

    /* check available memory */
    if (buf_mem > config.BufferTotalLimit) {
      l =
	snprintf (buffer, sizeof (buffer),
		  __ ("<%s> This hub is too busy, please try again later.|"), HUBSOFT_NAME);
      goto error;
    }

    /* client */
    cl = malloc (sizeof (client_t));
    if (!cl) {
      l =
	snprintf (buffer, sizeof (buffer),
		  __ ("<%s> This hub is too busy, please try again later.|"), HUBSOFT_NAME);

      goto error;
    }
    memset (cl, 0, sizeof (client_t));

    /* create new context */
    cl->proto = (proto_t *) s->context;
    cl->state = HUB_STATE_NORMAL;
    cl->user = cl->proto->user_alloc (cl);

    /* user connection refused. */
    if (!cl->user) {
      l =
	snprintf (buffer, sizeof (buffer),
		  __ ("<%s> This hub is too busy, please try again later.|"), HUBSOFT_NAME);

      goto error;
    }

    /* init some fields */
    cl->user->ipaddress = client_address.sin_addr.s_addr;
    cl->es = esocket_add_socket (s->handler, es_type_server, r, (uintptr_t) cl);

    if (!cl->es) {
      l =
	snprintf (buffer, sizeof (buffer),
		  __ ("<%s> This hub is too busy, please try again later.|"), HUBSOFT_NAME);

      goto error;
    }

    /* this can fail in case of IOCP... it will call server_handle_error and free everything */
    if (esocket_update_state (cl->es, SOCKSTATE_CONNECTED) < 0)
      return -1;

    DPRINTF (" Accepted %s user from %s\n", cl->proto->name, inet_ntoa (client_address.sin_addr));

    /* initiate connection */
    cl->proto->handle_token (cl->user, NULL);

    /* don't free this client if something goes wrong in the next loop! */
    cl = NULL;
  }

  return 0;

error:
#ifndef USE_WINDOWS
  /* if message, write it out */
  if (l)
    write (r, buffer, l);

  /* shut the socket down */
  shutdown (r, SHUT_RDWR);
  close (r);
#else
  {
    esocket_t *es = esocket_add_socket (s->handler, es_type_server, r, 0);

    if (es) {
      buffer_t *buf = bf_alloc (l);

      if (buf) {
	bf_memcpy (buf, buffer, l);
	es->state = SOCKSTATE_CONNECTED;
	if (l)
	  esocket_send (es, buf, 0);
	bf_free (buf);
      }
      esocket_remove_socket (es);
    } else {
      close (r);
    }
  }
#endif

  /* free any memory allocated */
  if (!cl)
    return -1;

  if (cl->user)
    cl->proto->user_free (cl->user);

  free (cl);

  return -1;
}

/*****************************************************************************
**                         INTERNAL UTILITIES                               **
*****************************************************************************/

/*
 * GENERIC NETWORK FUNCTIONS
 */
esocket_t *setup_incoming_socket (proto_t * proto, esocket_handler_t * h, unsigned int etype,
				  unsigned long address, int port)
{
  esocket_t *es;

#ifndef USE_WINDOWS
  int yes = 1;
#endif

  es = esocket_new (h, etype, AF_INET, SOCK_STREAM, 0, (uintptr_t) proto);
  if (!es) {
    perror ("socket:");
    return NULL;
  }
#ifndef USE_WINDOWS
  /* we make the socket reusable, so many ppl can connect here */
  if (setsockopt (es->socket, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof (yes)) < 0) {
    perror ("setsockopt (SO_REUSEADDR):");
    esocket_remove_socket (es);
    return NULL;
  }
#endif

  if (esocket_bind (es, address, port)) {
    esocket_remove_socket (es);
    return NULL;
  }

  /* start listening on the port */
  esocket_listen (es, 10, AF_INET, SOCK_STREAM, 0);

  esocket_update_state (es, SOCKSTATE_CONNECTED);
  esocket_setevents (es, ESOCKET_EVENT_IN);

  DPRINTF ("Listening for clients on port %d\n", port);

  return es;
}

/*****************************************************************************
**                         EXPORTED FUNCTIONS                               **
*****************************************************************************/

int server_isbuffering (client_t * cl)
{
  return cl->outgoing.count != 0;
}

int server_write_credit (client_t * cl, buffer_t * b)
{
  if (!cl)
    return 0;
  cl->credit += bf_size (b);
  return server_write (cl, b);
}

int server_write (client_t * cl, buffer_t * b)
{
  esocket_t *s;
  long l, w;
  unsigned long t;
  buffer_t *e;

  if (!cl)
    return 0;

  ASSERT (cl->es);
  if (!(s = cl->es))
    return 0;

  if (!bf_used (b))
    return 0;

  /* if data is queued, queue this after it */
  if (cl->outgoing.count) {
    /* if we are still below max buffer per user, queue buffer */
    if (((cl->outgoing.size - cl->offset) < (config.BufferHardLimit + cl->credit))
	&& (buf_mem < config.BufferTotalLimit)) {
      buf_mem -= cl->outgoing.size;
      string_list_add (&cl->outgoing, cl->user, b);
      buf_mem += cl->outgoing.size;
      BUF_DPRINTF (" %p Buffering %d buffers, %lu (%s).\n", cl->user, cl->outgoing.count,
		   cl->outgoing.size, cl->user->nick);
      /* if we are over the softlimit, we go into quick timeout mode */
      if ((cl->state == HUB_STATE_BUFFERING)
	  && ((cl->outgoing.size - cl->offset) >= (config.BufferSoftLimit + cl->credit))) {
	cl->state = HUB_STATE_OVERFLOW;
	server_settimer (cl, config.TimeoutOverflow);
      }
    }

    /* try sending some of that data */
    return server_handle_output (s);
  }

  /* write as much as we are able */
  w = l = t = 0;
  for (e = b; e; e = e->next) {
    l = bf_used (e);
    w = esocket_send (s, e, 0);
    if (w < 0) {
      switch (errno) {
	case EAGAIN:
	case ENOMEM:
	  break;
	case EPIPE:
#ifndef USE_WINDOWS
	case ECONNRESET:
#endif
	  DPRINTF ("server_write: write: %s\n", strerror (errno));
	  server_disconnect_user (cl, __ ("Connection closed."));
	  return -1;
	default:
	  DPRINTF ("server_write: write: %s\n", strerror (errno));
	  return -1;
      }
      w = 0;
      break;
    }
    hubstats.TotalBytesSend += w;
    if (w != l)
      break;
    t += l;
  }
  if (w > 0)
    t += w;

  if (cl->credit) {
    if (cl->credit > t) {
      cl->credit -= t;
    } else {
      cl->credit = 0;
    };
  }

  /* not everything could be written to socket. store the buffer 
   * and ask esocket to notify us as the socket becomes writable 
   */
  if (e) {
    ASSERT (!cl->outgoing.count);

    string_list_add (&cl->outgoing, cl->user, e);
    buffering++;
    buf_mem += cl->outgoing.size;
    cl->offset = w;
    esocket_addevents (s, ESOCKET_EVENT_OUT);

    if (cl->state == HUB_STATE_NORMAL) {
      if ((cl->outgoing.size - cl->offset) < (config.BufferSoftLimit + cl->credit)) {
	cl->state = HUB_STATE_BUFFERING;
	server_settimer (cl, config.TimeoutBuffering);
      } else {
	cl->state = HUB_STATE_OVERFLOW;
	server_settimer (cl, config.TimeoutOverflow);
      }
    }
    BUF_DPRINTF (" %p Starting to buffer... %lu (credit %lu)\n", cl->user, cl->outgoing.size,
		 cl->credit);
  };

  return t;
}

int server_disconnect_user (client_t * cl, char *reason)
{
  if (!cl)
    return 0;

  ASSERT (cl->state != HUB_STATE_CLOSED);
  if (cl->state == HUB_STATE_CLOSED)
    return 0;

  cl->state = HUB_STATE_CLOSED;

  /* first disconnect on protocol level: parting messages can be written */
  cl->proto->user_disconnect (cl->user, reason);

  /* cancel the timer */
  if (cl->timer) {
    etimer_free (cl->timer);
    cl->timer = NULL;
  }

  /* close the real socket */
  if (cl->es) {
    esocket_close (cl->es);
    esocket_remove_socket (cl->es);
    cl->es = NULL;
  }

  /* remove buffered outgoing data from total count */
  if (cl->outgoing.count) {
    STRINGLIST_VERIFY (&cl->outgoing);
    buf_mem -= cl->outgoing.size;
    buffering--;
  }

  /* clear buffered output buffers */
  string_list_clear (&cl->outgoing);

  /* free incoming buffers */
  if (cl->buffers) {
    bf_free (cl->buffers);
    cl->buffers = NULL;
  };

  /* free user */
  cl->proto->user_free (cl->user);

  free (cl);

  return 0;
}

int server_add_port (esocket_handler_t * h, proto_t * proto, unsigned long address, int port)
{
  return setup_incoming_socket (proto, h, es_type_listen, address, port) != NULL;
}

int server_setup (esocket_handler_t * h)
{
  es_type_listen = esocket_add_type (h, ESOCKET_EVENT_IN, accept_new_user, NULL, NULL);
  es_type_server =
    esocket_add_type (h, ESOCKET_EVENT_IN, server_handle_input, server_handle_output, server_error);

  iplist_init (&lastlist);

  return 0;
}

int server_init ()
{
  memset (&hubstats, 0, sizeof (hubstats));

  banlist_init (&hardbanlist);
  banlist_init (&softbanlist);

  core_config_init ();
  core_stats_init ();

  return 0;
}
