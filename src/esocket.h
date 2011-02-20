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

/*
 *  esocket statemachine
 *
 *   SOCKSTATE_INIT:
 *	sockets are created in this state.
 *	all calls are valid.
 *
 *   SOCKSTATE_RESOLVING:
 *	result from a call to esocket_connect
 *	no default events registered.
 *	
 *   SOCKSTATE_CONNECTING
 *	result from a call to esocket_connect after succesful resolving
 *	output event registered by default.
 *
 *   SOCKSTATE_CONNECTED,
 *	socket is connected and active. (also used for active listening sockets).
 *	default events as selecting in the are assigned type.
 *
 *   SOCKSTATE_CLOSING,
 *	socket is closing. (only used on IOCP)
 *	you should no longer access this socket in anyway.
 *	it should not generate events or timeouts.
 *
 *   SOCKSTATE_CLOSED,
 *	you should no longer access this socket in anyway.
 *	it should not generate events or timeouts.
 *
 *   SOCKSTATE_ERROR,
 *	error occured on the socket. close it.
 *	you should no longer access this socket in anyway.
 *	it should not generate events or timeouts.
 *
 *   SOCKSTATE_FREED      
 *	socket is in freelist.
 *	you should no longer access this socket in anyway.
 *	it should not generate events or timeouts.
 *
 */

#ifndef _ESOCKET_H_
#define _ESOCKET_H_

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#ifdef USE_WINDOWS
#undef HAVE_ARPA_INET_H
#undef HAVE_SYS_SOCKET_H
#undef HAVE_NETINET_IN_H
#undef HAVE_SYS_POLL_H
#endif

#include <sys/types.h>

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# else
   typedef void * uintptr_t;
# endif
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>

#ifdef USE_IOCP
#  include <winsock2.h>
#  include "etimer.h"
#else 
#  include <sys/socket.h>
#  include <netdb.h>
#  if !defined(HAVE_GETADDRINFO) || !defined(HAVE_GETNAMEINFO)
#    include "getaddrinfo.h"
#  endif
#  ifdef USE_PTHREADDNS
#    include "dns.h"
#  endif
#endif


#include "buffer.h"
#include "rbt.h"

#ifdef USE_EPOLL
#include <sys/epoll.h>
#define ESOCKET_MAX_FDS 	16384
#define ESOCKET_ASK_FDS 	2048
#endif

typedef enum {
 SOCKSTATE_INIT = 0,
 SOCKSTATE_RESOLVING,
 SOCKSTATE_CONNECTING,
 SOCKSTATE_CONNECTED,
 SOCKSTATE_CLOSING,
 SOCKSTATE_CLOSED,
 SOCKSTATE_ERROR,
 SOCKSTATE_FREED
} esocket_state_t;

#ifndef USE_EPOLL

#define ESOCKET_EVENT_IN	0x0001
#define ESOCKET_EVENT_OUT	0x0004
#define ESOCKET_EVENT_ERR	0x0008
#define ESOCKET_EVENT_HUP	0x0010

#else

#define ESOCKET_EVENT_IN	EPOLLIN
#define ESOCKET_EVENT_OUT	EPOLLOUT
#define ESOCKET_EVENT_ERR	EPOLLERR
#define ESOCKET_EVENT_HUP	EPOLLHUP

#endif

#ifndef USE_WINDOWS
#  define INVALID_SOCKET (-1)
#endif

typedef struct esocket esocket_t;
struct esockethandler;


#ifdef USE_IOCP

#ifndef LPFN_ACCEPTEX
typedef BOOL (WINAPI *LPFN_ACCEPTEX) (SOCKET,SOCKET,PVOID,DWORD,DWORD,DWORD,LPDWORD,LPOVERLAPPED);
#endif

typedef enum {
  ESIO_INVALID = 0,
  ESIO_READ,
  ESIO_WRITE,
  ESIO_WRITE_TRIGGER,
  ESIO_ACCEPT,
  ESIO_ACCEPT_TRIGGER,
  ESIO_RESOLVE,
  ESIO_CONNECT
} esocket_io_t;

typedef struct esocket_ioctx {
  WSAOVERLAPPED		Overlapped;
  
  struct esocket_ioctx  *next, *prev;

  esocket_t		*es;
  buffer_t		*buffer;
  unsigned long 	length;
  esocket_io_t		iotype;
  SOCKET		ioAccept;
  unsigned short	port;
  int 			family;
  int 			type;
  int 			protocol;
} esocket_ioctx_t;

#endif

/* enhanced sockets */
struct esocket {
  rbt_t rbt;
  struct esocket *next, *prev;	/* main socket list */

#ifdef USE_IOCP
  SOCKET socket;
  //struct AddrInfoEx *addr;
  struct addrinfo *addr;
#else
  int socket;
  struct addrinfo *addr;
#endif
  esocket_state_t state;
  unsigned int error;
  uintptr_t context;
  unsigned int type;
  uint32_t events;

  struct esockethandler *handler;

#ifdef USE_IOCP
  /* connect polling */
  etimer_t     timer;
  /* accept context */
  esocket_ioctx_t *ctxt;
  /* LPFN_ACCEPTEX fnAcceptEx; */
  LPWSAPROTOCOL_INFO protinfo;
  
  /* writes context */
  unsigned long outstanding;
  unsigned int  fragments;
  
  esocket_ioctx_t *ioclist;
#endif
};


/* define handler functions */
typedef int (input_handler_t) (esocket_t * s);
typedef int (output_handler_t) (esocket_t * s);
typedef int (error_handler_t) (esocket_t * s);

/* socket types */
typedef struct esockettypes {
  unsigned int type;
  input_handler_t *input;
  output_handler_t *output;
  error_handler_t *error;
  uint32_t default_events;
} esocket_type_t;

/* socket handler */
typedef struct esockethandler {
  esocket_type_t *types;
  unsigned int numtypes, curtypes;

  esocket_t *sockets;

#ifdef USE_SELECT
  fd_set input;
  fd_set output;
  fd_set error;

  int ni, no, ne;
#endif

#ifdef USE_EPOLL
  int epfd;
#endif

#ifdef USE_IOCP
  HANDLE iocp;
#endif

#ifdef USE_PTHREADDNS
  dns_t *dns;
#endif
  int n;
} esocket_handler_t;

/* function prototypes */
extern esocket_handler_t *esocket_create_handler (unsigned int numtypes);
extern int esocket_add_type (esocket_handler_t * h, unsigned int events,
				      input_handler_t input, output_handler_t output,
				      error_handler_t error);
extern esocket_t *esocket_new (esocket_handler_t * h, unsigned int etype, int domain, int type,
			       int protocol, uintptr_t context);
extern esocket_t *esocket_add_socket (esocket_handler_t * h, unsigned int type, int s,
                                      uintptr_t context);
extern int esocket_close (esocket_t * s);
extern int esocket_remove_socket (esocket_t * s);

extern int esocket_bind (esocket_t * s, unsigned long address, unsigned int port);

extern int esocket_connect (esocket_t * s, char *address, unsigned int port);

extern int esocket_select (esocket_handler_t * h, struct timeval *to);
extern int esocket_update (esocket_t * s, int fd, unsigned int state);
extern int esocket_update_state (esocket_t * s, unsigned int newstate);

extern int esocket_setevents (esocket_t * s, unsigned int events);
extern int esocket_addevents (esocket_t * s, unsigned int events);
extern int esocket_clearevents (esocket_t * s, unsigned int events);

#ifndef USE_IOCP
extern int esocket_accept (esocket_t *s, struct sockaddr *addr, int *addrlen);
#else
extern SOCKET esocket_accept (esocket_t *s, struct sockaddr *addr, int *addrlen);
#endif
extern int esocket_recv (esocket_t *s, buffer_t *buf);
extern int esocket_send (esocket_t *s, buffer_t *buf, unsigned long offset);
extern int esocket_listen (esocket_t *s, int num,int family, int type, int protocol);

#define esocket_hasevent(s,e)     (s->events & e)


/*
 *   These function allow more control over which actions to receive per socket.
 */

#endif /* _ESOCKET_H_ */
