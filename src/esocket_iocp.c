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

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <io.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#if (_WIN32_WINNT <= 0x0501)
void WSAAPI freeaddrinfo (struct addrinfo *);
int WSAAPI getaddrinfo (const char *, const char *, const struct addrinfo *, struct addrinfo **);
int WSAAPI getnameinfo (const struct sockaddr *, socklen_t, char *, DWORD, char *, DWORD, int);
#endif

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

//extern BOOL WSAAPI ConnectEx(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);


/******************************** IOCP specific stuff *******************************************/


/*
 *  These settings control the maximum writes outstanding per connection.
 *  the minimum write is 1/2 IOCP_COMPLETION_SIZE_MIN and max is 1/2 IOCP_COMPLETION_SIZE_MAX
 *  the MAX will use all outstanding locked memory for 1000 users and 1Gb memory
 *  the MIN was chosen at 2 tcp packets per fragment for throughput reasons. should support more than 10k users at 1Gb
 */

unsigned long iocpSendBuffer = 0;
unsigned long iocpFragments = 2;

#define IOCP_COMPLETION_FRAGMENTS iocpFragments
//#define IOCP_COMPLETION_FRAGMENTS 2
#define IOCP_COMPLETION_SIZE_MAX      131071
#define IOCP_COMPLETION_SIZE_MIN      2*1460*IOCP_COMPLETION_FRAGMENTS

#define close(x) closesocket(x)

#define IOCTX_FREE(ctxt) { ioctx_free (ctxt); free(ctxt); }
#define SYNC_ERRORS(socket) { errno = socket->error = translate_error(WSAGetLastError()); }

/* 
 *   connect polling interval
 */
#define IOCP_CONNECT_INTERVAL	250
#define IOCP_CLOSE_DEADLINE  	1000

/*
 * memory autotuning 
 */

/* here we keep track of the max outstanding request we have been able to do.
 * this is meant to represent the non-paged pool usage.
 *  If this becomes a problem we can adjust the pool with SetProcessWorkingSetSize
 */
#define OUTSTANDING_CHECK (outstanding < outstanding_max)
#define OUTSTANDING_INC	{ outstanding++; if (outstanding > outstanding_peak) outstanding_peak = outstanding; }
#define OUTSTANDING_DEC  { outstanding--; };
#define OUTSTANDING_FAILED { outstanding_max = outstanding_peak = outstanding; }

unsigned long outstanding = 0;
unsigned long outstanding_peak = 0;
unsigned long outstanding_max = ULONG_MAX;

/* here we keep track of the max outstanding write bytes we have been able to do.
 * this is meant to give us a good idea of the amount of memory we can lock.
 * we will use this to tune the outstanding bytes/connection
 */
#define OUTSTANDINGBYTES_CHECK(size) ( (outstandingbytes+size) < outstandingbytes_max)
#define OUTSTANDINGBYTES_INC(size)	{ outstandingbytes+=size; if (outstandingbytes > outstandingbytes_peak) { outstandingbytes_peak = outstandingbytes; USERS_UPDATE; }; }
#define OUTSTANDINGBYTES_DEC(size)  { outstandingbytes-=size; };
#define OUTSTANDINGBYTES_FAILED { outstandingbytes_max = outstandingbytes_peak = outstandingbytes; USERS_UPDATE; }

unsigned long outstandingbytes = 0;
unsigned long outstandingbytes_peak = 0;
unsigned long outstandingbytes_max = ULONG_MAX;

#define USERS_UPDATE	{ if (iocp_users) outstandingbytes_peruser = outstandingbytes_max / iocp_users; if (outstandingbytes_peruser < IOCP_COMPLETION_SIZE_MIN) outstandingbytes_peruser = IOCP_COMPLETION_SIZE_MIN; if (outstandingbytes_peruser> IOCP_COMPLETION_SIZE_MAX) outstandingbytes_peruser = IOCP_COMPLETION_SIZE_MAX; }
#define USERS_INC	{ iocp_users++; USERS_UPDATE; }
#define USERS_DEC	{ iocp_users--; USERS_UPDATE; }

unsigned long iocp_users = 0;
unsigned long outstandingbytes_peruser = IOCP_COMPLETION_SIZE_MAX;

unsigned char fake_buf;

int esocket_hard_close (esocket_t * s);

int esocket_timeout_close (esocket_t * s)
{
  return esocket_hard_close (s);
}

unsigned int translate_error (unsigned int winerror)
{
  switch (winerror) {
    case WSANOTINITIALISED:
      return ENOENT;

    case WSAENETDOWN:
      /* return ENETDOWN; */
      return ENOENT;

    case WSAEAFNOSUPPORT:
      /* return EAFNOSUPPORT; */
      return EINVAL;

    case WSAEPROTONOSUPPORT:
      /* return EPROTONOSUPPORT; */
      return EINVAL;

    case WSAEPROTOTYPE:
      /* return EPROTOTYPE; */
      return EINVAL;

    case WSAEWOULDBLOCK:
      return EAGAIN;

    case WSAEINPROGRESS:
      return EAGAIN;

    case WSAEMFILE:
      return EMFILE;

    case WSAENOBUFS:
      return ENOMEM;

    case WSAESOCKTNOSUPPORT:
      /* return ESOCKTNOSUPPORT; */
      return EINVAL;

    case WSAEINVAL:
      return EINVAL;

    case WSAEFAULT:
      return EFAULT;

    case WSAECONNABORTED:
      /* return ECONNABORTED; */
      return EPIPE;

    case WSAECONNRESET:
      /* return ECONNRESET; */
      return EPIPE;

    case WSAEDISCON:
      /* return ENOTCONN; */
      return EPIPE;

    case WSAEINTR:
      return EINTR;

    case WSAENETRESET:
      /* return ETIMEDOUT; */
      return EPIPE;

    case WSAENOTSOCK:
      /* return ENOTSOCK; */
      return EBADF;

    case WSA_IO_PENDING:
      /* return EINPROGRESS; */
      return EAGAIN;

    case WSA_OPERATION_ABORTED:
      return EINTR;

      /* this error is sometimes returned and means the socket is dead. */
    case ERROR_NETNAME_DELETED:
      return EPIPE;

  }
  /* unknown error... safest to assume the socket is toast. */
  return EPIPE;
}


esocket_ioctx_t *ioctx_alloc (esocket_t * s, int extralen)
{
  esocket_ioctx_t *ctxt = malloc (sizeof (esocket_ioctx_t) + extralen);

  if (!ctxt)
    return NULL;

  /* init to 0 */
  memset (ctxt, 0, sizeof (esocket_ioctx_t) + extralen);
  ctxt->es = s;

  /* link in list */
  ctxt->next = s->ioclist;
  if (ctxt->next)
    ctxt->next->prev = ctxt;
  ctxt->prev = NULL;
  s->ioclist = ctxt;

  return ctxt;
}


int ioctx_free (esocket_ioctx_t * ctxt)
{

  ASSERT (ctxt->es);

  /* remove from list */
  if (ctxt->next)
    ctxt->next->prev = ctxt->prev;
  if (ctxt->prev) {
    ctxt->prev->next = ctxt->next;
  } else {
    ctxt->es->ioclist = ctxt->next;
  }

  ctxt->es = NULL;
  ctxt->next = NULL;
  ctxt->prev = NULL;

  return 0;
}

int ioctx_flush (esocket_t * s)
{
  while (s->ioclist)
    ioctx_free (s->ioclist);

  return 0;
}

/* send error up */
int es_iocp_error (esocket_t * s)
{
  esocket_handler_t *h = s->handler;

  s->error = translate_error (WSAGetLastError ());

  if (h->types[s->type].error)
    h->types[s->type].error (s);

  return s->error;
}


int es_iocp_trigger (esocket_t * s, int type)
{
  esocket_ioctx_t *ctxt;

  if (s->state == SOCKSTATE_CLOSED)
    return -1;

  ctxt = ioctx_alloc (s, 0);
  if (!ctxt)
    return -1;

  ctxt->iotype = type;

  if (!PostQueuedCompletionStatus (s->handler->iocp, 0, (ULONG_PTR) s, &ctxt->Overlapped)) {
    perror ("PostQueuedCompletionStatus (send trigger):");
    IOCTX_FREE (ctxt);
    SYNC_ERRORS (s);
    return -1;
  }

  return 0;
}


/*    Queues a new 0 byte recv
 * This has a serious limitation! when you get an input event you MUST read
 * all the queued data.
 */

int es_iocp_recv (esocket_t * s)
{
  int ret;
  WSABUF buf;
  DWORD nrRecv = 0;
  DWORD dwFlags = 0;

  esocket_ioctx_t *ctxt = ioctx_alloc (s, 0);

  if (!ctxt)
    return -1;

  /* init context */
  ctxt->iotype = ESIO_READ;

  /* init buf to zero byte length */
  buf.buf = &fake_buf;
  buf.len = 0;
  ret = WSARecv (s->socket, &buf, 1, &nrRecv, &dwFlags, &ctxt->Overlapped, NULL);
  if (ret == SOCKET_ERROR) {
    int err = WSAGetLastError ();

    /* WSA_IO_PENDING means succesfull queueing */
    if (err != WSA_IO_PENDING) {
      IOCTX_FREE (ctxt);

      if (err == WSAENOBUFS)
	OUTSTANDING_FAILED;

      es_iocp_error (s);
      return -1;
    }
  }

  OUTSTANDING_INC;

  return 0;
}

int es_iocp_accept (esocket_t * s, int family, int type, int protocol)
{
  int ret, err;
  DWORD bytesReceived = 0;

  esocket_ioctx_t *ctxt = ioctx_alloc (s, (2 * (sizeof (SOCKADDR_STORAGE) + 16)));

  if (!ctxt)
    return -1;

  ctxt->ioAccept = WSASocket (family, type, protocol, s->protinfo, 0, WSA_FLAG_OVERLAPPED);
  if (ctxt->ioAccept == INVALID_SOCKET) {
    err = WSAGetLastError ();
    if (err == WSAENOBUFS)
      OUTSTANDING_FAILED;

    perror ("WSASocket (accept):");
    IOCTX_FREE (ctxt);
    SYNC_ERRORS (s);

    es_iocp_trigger (s, ESIO_ACCEPT_TRIGGER);

    return -1;
  }

  ctxt->iotype = ESIO_ACCEPT;
  ctxt->family = family;
  ctxt->type = type;
  ctxt->protocol = protocol;

  ret = /*s->fnAcceptEx */ AcceptEx (s->socket, ctxt->ioAccept, (ctxt + 1), 0,
				     (sizeof (SOCKADDR_STORAGE) + 16),
				     (sizeof (SOCKADDR_STORAGE) + 16), &bytesReceived,
				     &ctxt->Overlapped);
  err = WSAGetLastError ();
  if ((ret == SOCKET_ERROR) && (err != ERROR_IO_PENDING)) {
    if (err == WSAENOBUFS)
      OUTSTANDING_FAILED;
    perror ("fnAcceptEx:");
    IOCTX_FREE (ctxt);
    SYNC_ERRORS (s);

    es_iocp_trigger (s, ESIO_ACCEPT_TRIGGER);

    return -1;
  }

  /* what if it returns 0? AFAIK, this is also normal. Doc says ERROR_IO_PENDING is what it should return. */
  OUTSTANDING_INC;

  return 0;
}

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

  h->iocp = CreateIoCompletionPort (INVALID_HANDLE_VALUE, NULL, (ULONG_PTR) 0, 1);
  if (h->iocp == NULL) {
    perror ("CreateIoCompletionPort (Create)");
    free (h);
    return NULL;
  }
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
  if ((!(s->events & ESOCKET_EVENT_IN)) && (events & ESOCKET_EVENT_IN) && (!s->protinfo))
    if (es_iocp_recv (s) < 0)
      return -1;
  s->events = events;

  return 0;
}

int esocket_addevents (esocket_t * s, unsigned int events)
{
  if ((!(s->events & ESOCKET_EVENT_IN)) && (events & ESOCKET_EVENT_IN) && (!s->protinfo))
    if (es_iocp_recv (s) < 0)
      return -1;
  s->events |= events;

  return 0;
}

int esocket_clearevents (esocket_t * s, unsigned int events)
{
  s->events &= ~events;
  return 0;
}


int esocket_update_state (esocket_t * s, unsigned int newstate)
{
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
      s->events &= ~ESOCKET_EVENT_OUT;

      break;
    case SOCKSTATE_CONNECTED:
      /* remove according to requested callbacks */
      s->events = 0;

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
      s->events |= ESOCKET_EVENT_OUT;
      break;

    case SOCKSTATE_CONNECTED:
      /* add according to requested callbacks */
      if ((!(s->events & ESOCKET_EVENT_IN))
	  && (h->types[s->type].default_events & ESOCKET_EVENT_IN) && (!s->protinfo))
	if (es_iocp_recv (s) < 0)
	  return -1;

      s->events |= h->types[s->type].default_events;

      break;
    case SOCKSTATE_CLOSING:
      etimer_cancel (&s->timer);
      etimer_init (&s->timer, (etimer_handler_t *) esocket_timeout_close, s);
      etimer_set (&s->timer, IOCP_CLOSE_DEADLINE);
      break;

    case SOCKSTATE_CLOSED:
      ioctx_flush (s);
      break;

    case SOCKSTATE_ERROR:
    default:
      /* nothing to add */
      break;
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

  if (!iocpSendBuffer) {
    int len = 0;

    /* there is no sensible error handling we can do here. so we don't do any. */
    if (setsockopt (s, SOL_SOCKET, SO_SNDBUF, (char *) &len, sizeof (len)) != 0)
      goto remove;
  }

  if (CreateIoCompletionPort ((HANDLE) socket->socket, h->iocp, (ULONG_PTR) socket, 0) == NULL) {
    errno = translate_error (WSAGetLastError ());
    goto remove;
  }

  USERS_INC;

  return socket;

remove:
  h->sockets = socket->next;
  if (h->sockets)
    h->sockets->prev = NULL;
  free (socket);
  return NULL;
}

esocket_t *esocket_new (esocket_handler_t * h, unsigned int etype, int domain, int type,
			int protocol, uintptr_t context)
{
  int fd;
  esocket_t *s;

  if (etype >= h->curtypes)
    return NULL;

  fd = WSASocket (domain, type, protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
  if ((SOCKET) fd == INVALID_SOCKET) {
    errno = translate_error (WSAGetLastError ());
    return NULL;
  }

  {
    DWORD yes = 1;
    DWORD bytes = 0;

    if (WSAIoctl (fd, FIONBIO, &yes, sizeof (yes), NULL, 0, &bytes, NULL, NULL)) {
      errno = translate_error (WSAGetLastError ());
      perror ("WSAIoctl:");
      close (fd);
      return NULL;
    }
  }

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

  if (!iocpSendBuffer) {
    int len = 0;

    if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, (char *) &len, sizeof (len)))
      goto remove;
  }

  if (CreateIoCompletionPort ((HANDLE) s->socket, h->iocp, (ULONG_PTR) s, 0) == NULL) {
    errno = translate_error (WSAGetLastError ());
    goto remove;
  }

  USERS_INC;

  return s;

remove:
  h->sockets = s->next;
  if (h->sockets)
    h->sockets->prev = NULL;
  free (s);
  close (fd);
  return NULL;
}

int esocket_close (esocket_t * s)
{
  if (s->state == SOCKSTATE_CLOSING)
    return 0;

  if (s->fragments) {
    esocket_update_state (s, SOCKSTATE_CLOSING);
    return 0;
  }

  if (s->state == SOCKSTATE_CLOSED)
    return 0;

  esocket_update_state (s, SOCKSTATE_CLOSED);
  //FIXME shutdown (s->socket, SHUT_RDWR);
  close (s->socket);
  s->socket = INVALID_SOCKET;

  if (s->protinfo) {
    free (s->protinfo);
    s->protinfo = NULL;
  }

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
    errno = translate_error (WSAGetLastError ());
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

int esocket_check_connect (esocket_t * s)
{
  esocket_handler_t *h = s->handler;
  int err, len;
  struct sockaddr sa;

  s->error = 0;
  len = sizeof (sa);
  err = getpeername (s->socket, &sa, &len);
  if (err == SOCKET_ERROR) {
    err = WSAGetLastError ();
    if (err && (err != WSAEWOULDBLOCK)) {
      s->error = translate_error (err);
      goto error;
    }
    /* try again */
    etimer_set (&s->timer, IOCP_CONNECT_INTERVAL);
    return -1;
  }

  len = sizeof (s->error);
  err = getsockopt (s->socket, SOL_SOCKET, SO_ERROR, (void *) &s->error, &len);
  if (err) {
    err = WSAGetLastError ();
    s->error = translate_error (err);
    goto error;
  }

  if (s->error != 0) {
    s->error = translate_error (s->error);
    goto error;
  }

  DPRINTF ("Connecting and %s!\n", s->error ? "error" : "connected");

  err = s->error;
  esocket_update_state (s, !s->error ? SOCKSTATE_CONNECTED : SOCKSTATE_ERROR);

  if (!s->error) {
    if (h->types[s->type].output)
      h->types[s->type].output (s);
    return 0;
  }

error:
  if (h->types[s->type].error)
    h->types[s->type].error (s);

  return -1;
}

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

/*  ctxt = ioctx_alloc (s, 0);
  if (!ctxt)
    return -1;

  ctxt->iotype = ESIO_CONNECT;

  if ((err = ConnectEx (s->socket, s->addr->ai_addr, sizeof (struct sockaddr), NULL, 0, NULL, &ctxt->Overlapped))) {
    if ((err == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError ())) {
      perror ("ConnectEx:");
      IOCTX_FREE (ctxt);
      es_iocp_error (s);
      return -1;
    }
  }
*/

  err = connect (s->socket, s->addr->ai_addr, sizeof (struct sockaddr));
  if (err == SOCKET_ERROR) {
    err = WSAGetLastError ();
    if (err && (err != WSAEWOULDBLOCK)) {
      errno = translate_error (err);
      return -1;
    }
  }

  esocket_update_state (s, SOCKSTATE_CONNECTING);

  etimer_init (&s->timer, (etimer_handler_t *) esocket_check_connect, s);
  etimer_set (&s->timer, IOCP_CONNECT_INTERVAL);

  return 0;
}



#endif

/*
#else

int es_iocp_resolv (esocket_ioctx_t *ctxt) {
  esocket_t *s = ctxt->es;
  int err;
  esocket_ioctx_t *ctxt_connect;

  ctxt_connect = ioctx_alloc (s, 0);
  if (!ctxt_connect)
    return -1;

  ctxt->iotype = ESIO_CONNECT;

  ((struct sockaddr_in *) s->addr->ai_addr)->sin_port = htons (ctxt->port);

  if ((err = ConnectEx (s->socket, s->addr->ai_addr, sizeof (struct sockaddr), NULL, 0, NULL, &ctxt->Overlapped)) {
    if ((err == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError ())) {
      perror ("ConnectEx:");
      es_iocp_error (s);
      return -1;
    }
  }
  esocket_update_state (s, SOCKSTATE_CONNECTING);

  return 0;
}

int esocket_connect (esocket_t *s, char *address, unsigned int port) {
  struct esocket_ioctx_t *ctxt;
  
  int err;
  
  if (s->addr) {
    FreeAddrInfoEx (s->addr);
    s->addr = NULL;
  }
  
  ctxt = ioctx_alloc (s, 0);
  if (!ctxt)
    return -1;
  
  ctxt->iotype = ESIO_RESOLVE;
  ctxt->port   = port;
  
  if ((err = GetAddrInfoEx (address, NULL, NS_DNS, NULL, NULL, &s->addr, NULL, &ctx->Overlapped, NULL, NULL)) {
    if ((err == SOCKET_ERROR) && (ERROR_IO_PENDING != WSAGetLastError ())) {
      perror ("GetAddrInfoEx:");
      return -1;
    }
  };
  esocket_update_state (s, SOCKSTATE_RESOLVING);
  
  return 0;
}

#endif
*/

int esocket_hard_close (esocket_t * s)
{
  etimer_cancel (&s->timer);

  if (s->state != SOCKSTATE_CLOSED)
    esocket_update_state (s, SOCKSTATE_CLOSED);

  if (s->socket != INVALID_SOCKET) {
    close (s->socket);
    s->socket = INVALID_SOCKET;
  }

  if (s->protinfo) {
    free (s->protinfo);
    s->protinfo = NULL;
  }
  USERS_DEC;

  /* remove from list */
  if (s->next)
    s->next->prev = s->prev;
  if (s->prev) {
    s->prev->next = s->next;
  } else {
    s->handler->sockets = s->next;
  };

  /* put in freelist */
  s->next = freelist;
  freelist = s;
  s->prev = NULL;
  s->state = SOCKSTATE_FREED;

  return 1;

}

int esocket_remove_socket (esocket_t * s)
{
  if (!s)
    return 0;

  ASSERT (s->state != SOCKSTATE_FREED);

  if (s->state == SOCKSTATE_CLOSING)
    return 0;

  if (s->fragments) {
    esocket_update_state (s, SOCKSTATE_CLOSING);
    return 0;
  }

  return esocket_hard_close (s);
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
    SYNC_ERRORS (s);
    return ret;
  }

  buf->e += ret;

  return ret;
}


int esocket_send (esocket_t * s, buffer_t * buf, unsigned long offset)
{
  WSABUF wsabuf;
  int ret;
  unsigned int len, p, l, written;
  esocket_ioctx_t *ctxt;

  if (s->state != SOCKSTATE_CONNECTED) {
    errno = ENOENT;
    return -1;
  }

  if (s->fragments >= IOCP_COMPLETION_FRAGMENTS)
    goto leave;

  written = 0;
  p = outstandingbytes_peruser / IOCP_COMPLETION_FRAGMENTS;
  len = bf_used (buf) - offset;

  if (!len)
    return 0;

  while (len && (s->outstanding < outstandingbytes_peruser)
	 && (s->fragments < IOCP_COMPLETION_FRAGMENTS)) {
    //l = (len > p) ? p : len;
    l = len;
    wsabuf.buf = buf->s + offset;
    wsabuf.len = l;

    if (!OUTSTANDINGBYTES_CHECK (l)) {
      if (!s->fragments)
	es_iocp_trigger (s, ESIO_WRITE_TRIGGER);
      break;
    }

    /* alloc and init ioctx */
    ctxt = ioctx_alloc (s, 0);
    if (!ctxt)
      break;
    ctxt->buffer = buf;
    bf_claim (buf);
    ctxt->length = l;
    ctxt->iotype = ESIO_WRITE;

    /* send data */
    ret = WSASend (s->socket, &wsabuf, 1, NULL, 0, &ctxt->Overlapped, NULL);
    if (ret == SOCKET_ERROR) {
      int err = WSAGetLastError ();

      switch (err) {
	case WSA_IO_PENDING:
	  break;
	case WSAENOBUFS:
	case WSAEWOULDBLOCK:
	  bf_free (buf);
	  IOCTX_FREE (ctxt);

	  OUTSTANDINGBYTES_FAILED;

	  if (written)
	    return written;
	  errno = translate_error (err);
	  s->error = err;

	  if (!s->fragments)
	    es_iocp_trigger (s, ESIO_WRITE_TRIGGER);

	  return -1;
	default:
	  bf_free (buf);
	  IOCTX_FREE (ctxt);
	  errno = translate_error (err);
	  s->error = err;
	  return -1;
      }
    }

    OUTSTANDING_INC;
    OUTSTANDINGBYTES_INC (l);
    written += l;
    s->outstanding += l;
    offset += l;
    len -= l;
    s->fragments++;
  }

  if (written)
    return written;

leave:
  errno = EAGAIN;
  return -1;
}


SOCKET esocket_accept (esocket_t * s, struct sockaddr * addr, int *addrlen)
{
  SOCKET socket;
  struct sockaddr *addr1, *addr2;
  int len1 = 0, len2 = 0;
  esocket_ioctx_t *ctxt;
  void *p;

  if (!s->ctxt)
    return INVALID_SOCKET;

  ctxt = s->ctxt;

  p = (void *) (s->ctxt + 1);
  GetAcceptExSockaddrs (p, 0, (sizeof (SOCKADDR_STORAGE) + 16),
			(sizeof (SOCKADDR_STORAGE) + 16), &addr1, &len1, &addr2, &len2);

  socket = ctxt->ioAccept;

  if (addr && *addrlen)
    memcpy (addr, addr2, *addrlen);

  // FIXME error handling?
  setsockopt (socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *) &s->socket,
	      sizeof (s->socket));

  s->ctxt = NULL;

  es_iocp_accept (s, ctxt->family, ctxt->type, ctxt->protocol);

  return socket;
}

int esocket_listen (esocket_t * s, int num, int family, int type, int protocol)
{
  int ret, i;

  /*
     DWORD bytes = 0;
     GUID acceptex_guid = / * WSAID_ACCEPTEX * / { 0xb5367df1, 0xcbac, 0x11cf, {0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92}};
   */
  ret = listen (s->socket, 10);
  if (ret) {
    printf ("listen error %d\n", (int) WSAGetLastError ());
    perror ("listen");
    return ret;
  }

  i = sizeof (WSAPROTOCOL_INFO);
  s->protinfo = malloc (i);
  if (!s->protinfo) {
    errno = ENOMEM;
    return -1;
  }

  ret = getsockopt (s->socket, SOL_SOCKET, SO_PROTOCOL_INFO, (char *) s->protinfo, &i);
  if (ret == SOCKET_ERROR) {
    perror ("getsockopt (listen):");
    return -1;
  }

  /* retrieve fnAccept function *
     bytes = 0;
     ret = WSAIoctl (s->socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
     &acceptex_guid,
     sizeof (acceptex_guid),
     &s->fnAcceptEx, sizeof (s->fnAcceptEx), &bytes, NULL, NULL);
     if (ret == SOCKET_ERROR) {
     printf ("failed to load AcceptEx: %d\n", WSAGetLastError ());
     return -1;
     }
   */
  for (i = 0; i < num; i++)
    es_iocp_accept (s, family, type, protocol);

  return 0;
}


/************************************************************************
**
**                             IOCP
**
************************************************************************/

/*
 * process a write completion.
 */
unsigned int es_iocp_send (esocket_t * s, esocket_ioctx_t * ctxt)
{
  s->outstanding -= ctxt->length;
  OUTSTANDINGBYTES_DEC (ctxt->length);
  OUTSTANDING_DEC;
  s->fragments--;
  bf_free (ctxt->buffer);
  return 0;
}


int esocket_select (esocket_handler_t * h, struct timeval *to)
{
  esocket_t *s;
  esocket_ioctx_t *ctxt;

  BOOL ret;
  DWORD bytes = 0, count = 1000;
  OVERLAPPED *ol = NULL;
  DWORD ms = (to->tv_sec * 1000) + (to->tv_usec / 1000);

  for (; count; count--) {
    s = NULL;
    ol = NULL;
    ret = GetQueuedCompletionStatus (h->iocp, &bytes, (void *) &s, &ol, ms);
    if (!ret && !ol) {
      int err = GetLastError ();

      if (err != WAIT_TIMEOUT)
	printf ("GetQueuedCompletionStatus: %d\n", err);
      goto leave;
    }
    ms = 0;
    ctxt = (esocket_ioctx_t *) ol;
    /* this is a completion for a closed socket */
    ASSERT (ctxt);

    if (!ctxt->es) {
      if (ctxt->iotype == ESIO_WRITE) {
	bf_free (ctxt->buffer);
	OUTSTANDINGBYTES_DEC (ctxt->length);
      };
      OUTSTANDING_DEC;
      free (ctxt);
      continue;
    }
    ASSERT (s == ctxt->es);

    /* this is a completion for a socket with outstanding writes */
    if (s->state == SOCKSTATE_CLOSING) {
      if (ctxt->iotype == ESIO_WRITE) {
	bf_free (ctxt->buffer);
	OUTSTANDINGBYTES_DEC (ctxt->length);
	s->fragments--;
      };
      OUTSTANDING_DEC;
      ioctx_free (ctxt);
      free (ctxt);

      if (!s->fragments)
	esocket_hard_close (s);

      continue;
    }

    /* normal socket operation */
    if (s->state == SOCKSTATE_FREED)
      goto cont;
    if (s->socket == INVALID_SOCKET)
      goto cont;

    ioctx_free (ctxt);

    if (!ret) {
      SYNC_ERRORS (s);
      es_iocp_error (s);
      /*
       * we had an error and a socket dying on us.
       * according to the docs this happens when the client disconnects
       * before we had the chance of accepting his connection.
       *   close the socket and queue a new accept.
       */
      if (ctxt->iotype == ESIO_ACCEPT) {
	close (ctxt->ioAccept);
	es_iocp_accept (s, ctxt->family, ctxt->type, ctxt->protocol);
      }
      goto cont;
    }

    switch (ctxt->iotype) {
      case ESIO_READ:
	/* we had a read conpletion 
	 */
	OUTSTANDING_DEC;

	if (s->events & ESOCKET_EVENT_IN) {
	  if (h->types[s->type].input)
	    h->types[s->type].input (s);

	  if ((s->state == SOCKSTATE_FREED) || (s->state == SOCKSTATE_CLOSING))
	    goto cont;
	  if (s->socket == INVALID_SOCKET)
	    goto cont;

	  /* queue a new recv notification */
	  es_iocp_recv (s);
	}

	break;

      case ESIO_WRITE:
	/* first, process completion */
	ret = es_iocp_send (s, ctxt);

      case ESIO_WRITE_TRIGGER:
	/* call output function if requested */
	if ((s->events & ESOCKET_EVENT_OUT) && (h->types[s->type].output))
	  h->types[s->type].output (s);

	break;

      case ESIO_ACCEPT:
	s->ctxt = ctxt;

	if (h->types[s->type].input)
	  h->types[s->type].input (s);

	s->ctxt = NULL;

	OUTSTANDING_DEC;

	break;

      case ESIO_RESOLVE:
	//es_iocp_resolve(ctxt);
	break;

      case ESIO_CONNECT:

	//setsockopt(s->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

	//if (h->types[s->type].input)
	//  h->types[s->type].input (s);

	break;

      case ESIO_ACCEPT_TRIGGER:
	/* try queuing another accept request */
	if (s->protinfo)
	  es_iocp_accept (s, s->protinfo->iAddressFamily, s->protinfo->iSocketType,
			  s->protinfo->iProtocol);

	break;

      default:
	ASSERT (0);
    }

    fflush (stdout);
    fflush (stderr);
  cont:
    free (ctxt);
    ctxt = NULL;
  };

leave:
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
