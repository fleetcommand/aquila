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

#ifndef _PROTO_H_
#define _PROTO_H_

#ifdef USE_WINDOWS
#undef HAVE_ARPA_INET_H
#endif

#ifdef HAVE_ARPA_INET_H
#  include "arpa/inet.h"
#endif

#include "hashlist.h"
#include "buffer.h"
#include "config.h"
#include "leakybucket.h"
#include "tth.h"
#include "etimer.h"

#define PROTO_STATE_INIT         0	/* initial creation state */
#define PROTO_STATE_SENDLOCK     1	/* waiting for user $Key */
#define PROTO_STATE_WAITNICK     2	/* waiting for user $ValidateNick */
#define PROTO_STATE_WAITPASS     3	/* waiting for user $MyPass */
#define PROTO_STATE_HELLO        4	/* waiting for user $MyInfo */
#define PROTO_STATE_ONLINE       5	/* uaser is online and active */
#define PROTO_STATE_DISCONNECTED 6	/* user is disconnected */
#define PROTO_STATE_VIRTUAL	  7	/* this is a "fake" user, for robots */

/* everything in ms */
#define PROTO_TIMEOUT_INIT		5000	/* initial creation state */
#define PROTO_TIMEOUT_SENDLOCK 		5000	/* waiting for user $Key */
#define PROTO_TIMEOUT_WAITNICK		5000	/* waiting for user $ValidateNick */
#define PROTO_TIMEOUT_WAITPASS		30000	/* waiting for user $MyPass */
#define PROTO_TIMEOUT_HELLO		5000	/* waiting for user $MyInfo */
#define PROTO_TIMEOUT_ONLINE		300000	/* send $ForceMove command to user */

#define PROTO_FLAG_MASK			0xffff	/* use this to remove protocol specific flags. */
#define PROTO_FLAG_HUBSEC		1
#define PROTO_FLAG_REGISTERED		2
#define PROTO_FLAG_ZOMBIE		4

/* FIXME split of nmdc specific fields */
typedef struct user {
  hashlist_entry_t hash;
  struct user *next, *prev;

  int state;			/* current connection state */

  unsigned char nick[NICKLENGTH];
  unsigned long supports;

  unsigned long long share;	/* share size */
  int active;			/* active? 1: active, 0: passive, -1: invalid */
  unsigned int slots;		/* slots user have open */
  unsigned int hubs[3];		/* hubs user is in */
  unsigned long ipaddress;	/* ip address */
  unsigned char client[64];	/* client used */
  unsigned char versionstring[64];	/* client version */
  double version;
  unsigned int op;
  unsigned int flags;
  unsigned long long rights;

  etimer_t	timer;

  /* user data */
  unsigned char lock[LOCKLENGTH];
  unsigned long joinstamp;

  /* plugin private user data */
  void *plugin_priv;

  /* rate limiting counters */
  leaky_bucket_t rate_warnings;
  leaky_bucket_t rate_violations;
  leaky_bucket_t rate_chat;
  leaky_bucket_t rate_search;
  leaky_bucket_t rate_myinfo;
  leaky_bucket_t rate_myinfoop;
  leaky_bucket_t rate_getnicklist;
  leaky_bucket_t rate_getinfo;
  leaky_bucket_t rate_downloads;
  leaky_bucket_t rate_psresults_in;
  leaky_bucket_t rate_psresults_out;

  /* cache counters */
  unsigned int ChatCnt, SearchCnt, ResultCnt, MessageCnt;
  unsigned int CacheException;

  /* search caching */
  tth_list_t *tthlist;

  /* cache data */
  buffer_t *MyINFO;

  /* pointer for protocol private data */
  void *pdata;

  /* back linking pointer for parent */
  void *parent;
} user_t;

typedef struct {
  int (*init) (void);
  int (*setup) (void);

  int (*handle_input) (user_t * user, buffer_t ** buffers);
  int (*handle_token) (user_t *, buffer_t *);
  void (*flush_cache) (void);

  user_t *(*user_alloc) (void *priv);
  int (*user_free) (user_t *);

  int (*user_disconnect) (user_t *, char *);

  int (*user_forcemove) (user_t *, unsigned char *, buffer_t *);
  int (*user_redirect) (user_t *, buffer_t *);
  int (*user_drop) (user_t *, buffer_t *);
  user_t *(*user_find) (unsigned char *);

  user_t *(*robot_add) (unsigned char *nick, unsigned char *description);
  int (*robot_del) (user_t *);

  int (*chat_main) (user_t *, buffer_t *);
  int (*chat_send) (user_t *, user_t *, buffer_t *);
  int (*chat_send_direct) (user_t *, user_t *, buffer_t *);
  int (*chat_priv) (user_t *, user_t *, user_t *, buffer_t *);
  int (*chat_priv_direct) (user_t *, user_t *, user_t *, buffer_t *);
  int (*raw_send) (user_t *, buffer_t *);
  int (*raw_send_all) (buffer_t *);

  unsigned char *name;
} proto_t;

#endif /* _PROTO_H_ */
