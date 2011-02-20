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

#ifndef _DNS_H_
#define _DNS_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>

#define HAVE_GETHOSTBYNAME_R
                     
typedef struct dns_request dns_request_t;

struct dns_request {
  struct dns_request *next, *prev;
  unsigned char *node;
  struct addrinfo *addr;
  unsigned int error;
  void * ctxt;
};

typedef struct dns {
  pthread_t thread;

  /* sync objects */
  pthread_mutex_t  mutex;
  pthread_cond_t   cond;
  
  /* protected tasklists */
  dns_request_t tasklist;
  dns_request_t resultlist;
} dns_t;

extern int dns_resolve (dns_t *dns, void * ctxt, unsigned char *name);
extern void *dns_retrieve (dns_t *, struct addrinfo **addr);
extern dns_t * dns_init ();

#endif
