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

#ifndef _HUB_H_
#define _HUB_H_

#include "esocket.h"

#ifndef __USE_W32_SOCKETS
#  include <arpa/inet.h>
#endif

#include "config.h"
#include "buffer.h"
#include "proto.h"
#include "stringlist.h"
#include "banlist.h"
#include "etimer.h"

/* local timeouts */

#define HUB_STATE_NORMAL	1
#define HUB_STATE_BUFFERING	2
#define HUB_STATE_OVERFLOW	3
#define HUB_STATE_CLOSED	4

typedef struct hub_statitics {
  unsigned long long TotalBytesSend;
  unsigned long long TotalBytesReceived;
} hub_statistics_t;

extern hub_statistics_t hubstats;

/*
 *  server private context.
 */

typedef struct client {
  proto_t *proto;
  esocket_t *es;
  buffer_t *buffers;		/* contains read but unparsed buffers */
  string_list_t outgoing;
  unsigned long offset, credit;
  unsigned int state;
  etimer_t	*timer;

  user_t *user;
} client_t;

extern unsigned long users;

/*  banlists */
extern unsigned long buffering;
extern banlist_t hardbanlist, softbanlist;
//extern banlist_nick_t nickbanlist;

extern int server_init ();
extern int server_setup (esocket_handler_t *);
extern int server_disconnect_user (client_t *, char *);
extern int server_write (client_t *, buffer_t *);
extern int server_write_credit (client_t *, buffer_t *);
extern int server_add_port (esocket_handler_t * h, proto_t * proto,  unsigned long address, int port);
extern int server_isbuffering (client_t *);

#endif /* _HUB_H_ */
