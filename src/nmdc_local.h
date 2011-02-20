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

 #ifndef _NMDC_LOCAL_H_
#define _NMDC_LOCAL_H_

#include "proto.h"
#include "nmdc_protocol.h"

extern cache_t cache;
extern ratelimiting_t rates;
extern user_t *userlist;
extern hashlist_t hashlist;

extern user_t *   cachelist;
extern user_t *   cachelist_last;
extern hashlist_t cachehashlist;

extern user_t *HubSec;

extern unsigned int keylen;
extern unsigned int keyoffset;
extern char key[16 + sizeof (LOCK) + 4 + LOCKLENGTH + 1];

extern banlist_t reconnectbanlist;

extern unsigned int cloning;

extern unsigned int notimeout;

extern unsigned char *nickchars;
extern unsigned char nickchar_map[256];
extern unsigned char nmdc_forbiddenchars[256];

extern unsigned int chatmaxlength;
extern unsigned int searchmaxlength;
extern unsigned int srmaxlength;
extern unsigned int researchmininterval, researchperiod, researchmaxcount;

extern unsigned char *defaultbanmessage;

/* function prototypes */
extern int proto_nmdc_setup ();
extern int proto_nmdc_init ();
extern int proto_nmdc_handle_token (user_t * u, buffer_t * b);
extern int proto_nmdc_handle_input (user_t * user, buffer_t ** buffers);
extern void proto_nmdc_flush_cache ();
extern int proto_nmdc_user_disconnect (user_t * u, char *);
extern int proto_nmdc_user_forcemove (user_t * u, unsigned char *destination, buffer_t * message);
extern int proto_nmdc_user_redirect (user_t * u, buffer_t * message);
extern int proto_nmdc_user_drop (user_t * u, buffer_t * message);
extern user_t *proto_nmdc_user_find (unsigned char *nick);
extern user_t *proto_nmdc_user_alloc (void *priv);
extern int proto_nmdc_user_free (user_t * user);

extern user_t *proto_nmdc_user_addrobot (unsigned char *nick, unsigned char *description);
extern int proto_nmdc_user_delrobot (user_t * u);

extern int proto_nmdc_user_say_pm (user_t * u, user_t * target, user_t * src, buffer_t * b, buffer_t * message);
extern int proto_nmdc_user_say (user_t * u, buffer_t * b, buffer_t * message);
extern int proto_nmdc_user_say_string (user_t * u, buffer_t * b, unsigned char *message);

extern int proto_nmdc_user_warn (user_t * u, struct timeval *now, unsigned char *message, ...);

extern int proto_nmdc_user_chat_all (user_t * u, buffer_t * message);
extern int proto_nmdc_user_send (user_t * u, user_t * target, buffer_t * message);
extern int proto_nmdc_user_send_direct (user_t * u, user_t * target, buffer_t * message);
extern int proto_nmdc_user_priv (user_t * u, user_t * target, user_t * source, buffer_t * message);
extern int proto_nmdc_user_priv_direct (user_t * u, user_t * target, user_t * source, buffer_t * message);
extern int proto_nmdc_user_raw (user_t * target, buffer_t * message);
extern int proto_nmdc_user_raw_all (buffer_t * message);

extern int proto_nmdc_user_userip2 (user_t *target);

extern void proto_nmdc_user_cachelist_add (user_t *user);
extern void proto_nmdc_user_cachelist_invalidate (user_t *u);
extern void proto_nmdc_user_cachelist_clear ();

extern int proto_nmdc_violation (user_t * u, struct timeval *now, char *reason);

#endif
