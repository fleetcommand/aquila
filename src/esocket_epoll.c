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

#include "esocket.h"
#include "etimer.h"

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#ifndef ASSERT
#  ifdef DEBUG
#    define ASSERT assert
#  else
#    define ASSERT(...)
#  endif
#endif

#ifndef DPRINTF
#  ifdef DEBUG
#     define DPRINTF printf
#  else
#    define DPRINTF(...)
#  endif
#endif

esocket_t *freelist = NULL;

/*
 * Handler functions
 */
esocket_handler_t *esocket_create_handler (unsigned int numtypes)
{
  esocket_handler_t *h;

  h = malloc (sizeof (esocket_handler_t));
  if (!h)
    return NULL;
  memset (h, 0, sizeof (esocket_handler_t));

  h->types = malloc (sizeof (esocket_type_t) * numtypes);
  if (!h->types) {
    free (h);
    return NULL;
  }
  memset (h->types, 0, sizeof (esocket_type_t) * numtypes);
  h->numtypes = numtypes;
  h->epfd = epoll_create (ESOCKET_MAX_FDS);

#ifdef USE_PTHREADDNS
  h->dns = dns_init ();
#endif

  return h;
}

int esocket_add_type (esocket_handler_t * h, unsigned int events,
		      input_handler_t input, output_handler_t output, error_handler_t error)
{
  if (h->curtypes == h->numtypes)
    return -1;

  h->types[h->curtypes].type = h->curtypes;
  h->types[h->curtypes].input = input;
  h->types[h->curtypes].output = output;
  h->types[h->curtypes].error = error;

  h->types[h->curtypes].default_events = events;

  return h->curtypes++;
}


/*
 * Socket functions
 */

int esocket_setevents (esocket_t * s, unsigned int events)
{
  esocket_handler_t *h = s->handler;

  if (events != s->events) {
    struct epoll_event ee;

    ee.events = events;
    ee.data.ptr = s;
    epoll_ctl (h->epfd,
	       events ? (s->
			 events ? EPOLL_CTL_MOD : EPOLL_CTL_ADD) : EPOLL_CTL_DEL, s->socket, &ee);
    s->events = events;
  }

  return 0;
}

int esocket_addevents (esocket_t * s, unsigned int events)
{
  esocket_handler_t *h = s->handler;

  if ((events | s->events) != s->events) {
    struct epoll_event ee;

    memset (&ee, 0, sizeof (ee));
    ee.events = s->events | events;
    ee.data.ptr = s;
    epoll_ctl (h->epfd,
	       ee.events ? (s->
			    events ? EPOLL_CTL_MOD : EPOLL_CTL_ADD) :
	       EPOLL_CTL_DEL, s->socket, &ee);
    s->events = ee.events;
  }

  return 0;
}

int esocket_clearevents (esocket_t * s, unsigned int events)
{
  esocket_handler_t *h = s->handler;

  if (events & s->events) {
    struct epoll_event ee;

    memset (&ee, 0, sizeof (ee));
    ee.events = s->events & ~events;
    ee.data.ptr = s;
    epoll_ctl (h->epfd,
	       ee.events ? (s->
			    events ? EPOLL_CTL_MOD : EPOLL_CTL_ADD) :
	       EPOLL_CTL_DEL, s->socket, &ee);
    s->events = ee.events;
  }

  return 0;
}


int esocket_update_state (esocket_t * s, unsigned int newstate)
{
  uint32_t events = 0;

  esocket_handler_t *h = s->handler;

  if (s->state == newstate)
    return 0;

  /* first, remove old state */
  switch (s->state) {
    case SOCKSTATE_INIT:
      /* nothing to remove */
      break;
    case SOCKSTATE_CONNECTING:
      /* remove the wait for connect" */
      events &= ~EPOLLOUT;

      break;
    case SOCKSTATE_CONNECTED:
      /* remove according to requested callbacks */
      events &= ~s->events;

      break;
    case SOCKSTATE_CLOSED:
    case SOCKSTATE_CLOSING:
    case SOCKSTATE_ERROR:
    default:
      /* nothing to remove */
      break;
  }

  s->state = newstate;

  /* add new state */
  switch (s->state) {
    case SOCKSTATE_INIT:
      /* nothing to add */
      break;
    case SOCKSTATE_CONNECTING:
      /* add to wait for connect */
      events |= EPOLLOUT;

      break;
    case SOCKSTATE_CONNECTED:
      /* add according to requested callbacks */
      events |= h->types[s->type].default_events;

      break;
    case SOCKSTATE_CLOSING:
      break;

    case SOCKSTATE_CLOSED:
    case SOCKSTATE_ERROR:
    default:
      /* nothing to add */
      break;
  }

  if (events != s->events) {
    struct epoll_event ee;

    ee.events = events;
    ee.data.ptr = s;
    epoll_ctl (h->epfd,
	       ee.events ? (s->
			    events ? EPOLL_CTL_MOD : EPOLL_CTL_ADD) :
	       EPOLL_CTL_DEL, s->socket, &ee);
    s->events = events;
  }

  return 0;
}

esocket_t *esocket_add_socket (esocket_handler_t * h, unsigned int type, int s, uintptr_t context)
{
  esocket_t *socket;

  if (type >= h->curtypes)
    return NULL;

  socket = malloc (sizeof (esocket_t));
  if (!socket)
    return NULL;

  memset (socket, 0, sizeof (esocket_t));
  socket->type = type;
  socket->socket = s;
  socket->context = context;
  socket->handler = h;
  socket->state = SOCKSTATE_INIT;
  socket->addr = NULL;
  socket->events = 0;

  socket->prev = NULL;
  socket->next = h->sockets;
  if (socket->next)
    socket->next->prev = socket;
  h->sockets = socket;


  if (s == -1)
    return socket;

  return socket;
}

esocket_t *esocket_new (esocket_handler_t * h, unsigned int etype, int domain, int type,
			int protocol, uintptr_t context)
{
  int fd;
  esocket_t *s;

  if (etype >= h->curtypes)
    return NULL;

  fd = socket (domain, type, protocol);
  if (fd < 0)
    return NULL;

  if (fcntl (fd, F_SETFL, O_NONBLOCK)) {
    perror ("ioctl()");
    close (fd);
    return NULL;
  };

  s = malloc (sizeof (esocket_t));
  if (!s)
    return NULL;

  memset (s, 0, sizeof (esocket_t));
  s->type = etype;
  s->socket = fd;
  s->context = context;
  s->handler = h;
  s->state = SOCKSTATE_INIT;
  s->events = 0;
  s->addr = NULL;

  s->prev = NULL;
  s->next = h->sockets;
  if (s->next)
    s->next->prev = s;
  h->sockets = s;


  if (fd == -1)
    return s;

  return s;
}

int esocket_close (esocket_t * s)
{
  if (s->state == SOCKSTATE_CLOSED)
    return 0;

  esocket_update_state (s, SOCKSTATE_CLOSED);
  //FIXME shutdown (s->socket, SHUT_RDWR);
  close (s->socket);
  s->socket = INVALID_SOCKET;

  return 0;
}

int esocket_bind (esocket_t * s, unsigned long address, unsigned int port)
{
  struct sockaddr_in a;

  /* init the socket address structure */
  memset (&a, 0, sizeof (a));
  a.sin_addr.s_addr = address;
  a.sin_port = htons (port);
  a.sin_family = AF_INET;

  /* bind the socket to the local port */
  if (bind (s->socket, (struct sockaddr *) &a, sizeof (a))) {
    perror ("bind:");
    return -1;
  }

  return 0;
}

#ifdef USE_PTHREADDNS
int esocket_connect (esocket_t * s, char *address, unsigned int port)
{
  dns_resolve (s->handler->dns, s, address);

  /* abusing the error member to store the port. */
  s->error = port;

  esocket_update_state (s, SOCKSTATE_RESOLVING);

  return 0;
}

int esocket_connect_ai (esocket_t * s, struct addrinfo *address, unsigned int port)
{
  int err;
  struct sockaddr_in ai;

  if (s->state != SOCKSTATE_RESOLVING)
    return -1;

  if (!address) {
    s->error = ENXIO;
    if (s->handler->types[s->type].error)
      s->handler->types[s->type].error (s);
    return -1;
  }

  s->addr = address;

  ai = *((struct sockaddr_in *) address->ai_addr);
  ai.sin_port = htons (port);

  err = connect (s->socket, (struct sockaddr *) &ai, sizeof (struct sockaddr));
  esocket_update_state (s, SOCKSTATE_CONNECTING);

  return 0;
}

#else
int esocket_connect (esocket_t * s, char *address, unsigned int port)
{
  int err;

  //esocket_ioctx_t *ctxt;

  if (s->addr)
    freeaddrinfo (s->addr);

  if ((err = getaddrinfo (address, NULL, NULL, &s->addr))) {
    errno = translate_error (WSAGetLastError ());
    return -1;
  }

  ((struct sockaddr_in *) s->addr->ai_addr)->sin_port = htons (port);

  err = connect (s->socket, s->addr->ai_addr, sizeof (struct sockaddr));
  if (err == SOCKET_ERROR) {
    err = WSAGetLastError ();
    if (err && (err != WSAEWOULDBLOCK)) {
      errno = translate_error (err);
      return -1;
    }
  }

  esocket_update_state (s, SOCKSTATE_CONNECTING);

  return 0;
}

#endif

int esocket_remove_socket (esocket_t * s)
{
  esocket_handler_t *h;

  if (!s)
    return 0;

  ASSERT (s->state != SOCKSTATE_FREED);

  h = s->handler;

  if (s->state != SOCKSTATE_CLOSED)
    esocket_update_state (s, SOCKSTATE_CLOSED);

  if (s->socket != INVALID_SOCKET) {
    close (s->socket);
    s->socket = INVALID_SOCKET;
  }

  /* remove from list */
  if (s->next)
    s->next->prev = s->prev;
  if (s->prev) {
    s->prev->next = s->next;
  } else {
    h->sockets = s->next;
  };

  /* put in freelist */
  s->next = freelist;
  freelist = s;
  s->prev = NULL;
  s->state = SOCKSTATE_FREED;

  return 1;
}

int esocket_update (esocket_t * s, int fd, unsigned int sockstate)
{
  esocket_update_state (s, SOCKSTATE_CLOSED);
  s->socket = fd;
  esocket_update_state (s, sockstate);

  return 1;
}

/************************************************************************
**
**                             IO Functions
**
************************************************************************/

int esocket_recv (esocket_t * s, buffer_t * buf)
{
  int ret;

  if (s->state != SOCKSTATE_CONNECTED) {
    errno = ENOENT;
    return -1;
  }

  ret = recv (s->socket, buf->e, bf_unused (buf), 0);
  if (ret < 0) {
    return ret;
  }

  buf->e += ret;

  return ret;
}


int esocket_send (esocket_t * s, buffer_t * buf, unsigned long offset)
{
  return send (s->socket, buf->s + offset, bf_used (buf) - offset, 0);
}


int esocket_accept (esocket_t * s, struct sockaddr *addr, int *addrlen)
{
  return accept (s->socket, addr, addrlen);
}

int esocket_listen (esocket_t * s, int num, int family, int type, int protocol)
{
  return listen (s->socket, num);
}


/************************************************************************
**
**                             EPOLL
**
************************************************************************/

int esocket_select (esocket_handler_t * h, struct timeval *to)
{
  int num, i;
  uint32_t activity;
  esocket_t *s;
  struct epoll_event events[ESOCKET_ASK_FDS];

#ifdef USE_PTHREADDNS
  struct addrinfo *res;
#endif

  num = epoll_wait (h->epfd, events, ESOCKET_ASK_FDS, to->tv_sec * 1000 + to->tv_usec / 1000);
  if (num < 0) {
    perror ("ESocket: epoll_wait: ");
    return -1;
  }

  for (i = 0; i < num; i++) {
    activity = events[i].events;
    s = events[i].data.ptr;
    if (s->state == SOCKSTATE_FREED)
      continue;

    if (activity & EPOLLHUP) {
      int err;
      unsigned int len;

      len = sizeof (s->error);
      err = getsockopt (s->socket, SOL_SOCKET, SO_ERROR, &s->error, &len);
      ASSERT (!err);

      if (h->types[s->type].error)
	h->types[s->type].error (s);

      ASSERT (s->state == SOCKSTATE_FREED);
      continue;
    }
    if (activity & EPOLLERR) {
      int err;
      unsigned int len;

      len = sizeof (s->error);
      err = getsockopt (s->socket, SOL_SOCKET, SO_ERROR, &s->error, &len);
      ASSERT (!err);

      if (h->types[s->type].error)
	h->types[s->type].error (s);
      if (s->state == SOCKSTATE_FREED)
	continue;
      if (s->socket < 0)
	continue;
    }
    if (activity & EPOLLIN) {
      if (h->types[s->type].input)
	h->types[s->type].input (s);
      if (s->state == SOCKSTATE_FREED)
	continue;
      if (s->socket < 0)
	continue;
    }
    if (activity & EPOLLOUT) {
      switch (s->state) {
	case SOCKSTATE_CONNECTED:
	  if (h->types[s->type].output)
	    h->types[s->type].output (s);
	  break;
	case SOCKSTATE_CONNECTING:
	  {
	    int err;
	    unsigned int len;

	    len = sizeof (s->error);
	    err = getsockopt (s->socket, SOL_SOCKET, SO_ERROR, &s->error, &len);
	    ASSERT (!err);
	    esocket_update_state (s, !s->error ? SOCKSTATE_CONNECTED : SOCKSTATE_ERROR);
	    if (s->error) {
	      if (h->types[s->type].error)
		h->types[s->type].error (s);
	    } else {
	      if (h->types[s->type].output)
		h->types[s->type].output (s);
	    }
	  }
	  break;
	case SOCKSTATE_FREED:
	default:
	  ASSERT (0);
      }
      if (s->state == SOCKSTATE_FREED)
	continue;
      if (s->socket < 0)
	continue;
    }
  }

#ifdef USE_PTHREADDNS
  /* dns stuff */
  while ((s = dns_retrieve (h->dns, &res))) {
    if (esocket_connect_ai (s, res, s->error) < 0)
      freeaddrinfo (res);
  }
#endif

  /* timer stuff */
  etimer_checktimers ();

  /* clear freelist */
  while (freelist) {
    s = freelist;
    freelist = s->next;
    if (s->addr) {
      freeaddrinfo (s->addr);
      s->addr = NULL;
    }
    free (s);
  }

  return 0;
}
