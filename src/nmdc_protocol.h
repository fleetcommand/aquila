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

#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "stringlist.h"
#include "cap.h"
#include "leakybucket.h"
#include "nmdc_nicklistcache.h"

/*
 * Adress is local if: 10.0.0.0/8, 192.168.0.0/16, 169.254.0.0/16 172.16.0.0/16 or 127.0.0.1
 */

#define ISLOCAL(ip)	( ((ip & ntohl(0xFF000000)) == ntohl(0x0A000000)) \
                       || ((ip & ntohl(0xFFFF0000)) == ntohl(0xC0A80000)) \
                       || ((ip & ntohl(0xFFFF0000)) == ntohl(0xA9FE0000)) \
                       || ((ip & ntohl(0xFFFF0000)) == ntohl(0xAC100000)) \
                       || (ip == ntohl(0x7F000001)))

#define PROTOCOL_REBUILD_PERIOD	3

#define NMDC_SUPPORTS_NoGetINFO       1	/* no need for GetINFOs */
#define NMDC_SUPPORTS_NoHello         2	/* no $Hello for new signons */
#define NMDC_SUPPORTS_UserCommand     4	/* */
#define NMDC_SUPPORTS_UserIP2	      8	/* */
#define NMDC_SUPPORTS_QuickList      16	/* NOT SUPPORTED ! deprecated. */
#define NMDC_SUPPORTS_TTHSearch      32	/* client can handle TTH searches */

#define NMDC_SUPPORTS_ZPipe		1024	/* */
#define NMDC_SUPPORTS_ZLine		2048	/* */

#define NMDC_FLAG_DELAYEDNICKLIST	0x00010000
#define NMDC_FLAG_BOT			0x00020000
#define NMDC_FLAG_CACHED		0x00040000
#define NMDC_FLAG_WASKICKED		0x40000000
#define NMDC_FLAG_WASONLINE		0x80000000

typedef struct ratelimiting {
  leaky_bucket_type_t warnings;
  leaky_bucket_type_t violations;
  leaky_bucket_type_t chat;
  leaky_bucket_type_t asearch;
  leaky_bucket_type_t psearch;
  leaky_bucket_type_t research;
  leaky_bucket_type_t myinfo;
  leaky_bucket_type_t myinfoop;
  leaky_bucket_type_t getnicklist;
  leaky_bucket_type_t getinfo;
  leaky_bucket_type_t downloads;
  leaky_bucket_type_t connects;
  leaky_bucket_type_t psresults_in;
  leaky_bucket_type_t psresults_out;
} ratelimiting_t;

extern ratelimiting_t rates;

typedef struct nmdc_user {
  cache_element_t privatemessages;
  cache_element_t results;
} nmdc_user_t;

typedef struct {
  unsigned long cacherebuild;	/* rebuild of nick list cache */
  unsigned long userjoin;	/* all user joins */
  unsigned long userpart;	/* all user parts */
  unsigned long userviolate;	/* all user that are kicked for rate violations */
  unsigned long banned;		/* all forcemoves  for banned users */
  unsigned long forcemove;	/* all forcemoves */
  unsigned long disconnect;	/* all drops/disconnects */
  unsigned long redirect;	/* all redirects */
  unsigned long tokens;		/* all tokens processed */
  unsigned long brokenkey;	/* all users refused cuz of broken key */
  unsigned long badnick;	/* all users refused cuz of illegal chars in nickname */
  unsigned long usednick;	/* all users refused cuz of nickname already used */
  unsigned long mynick;		/* all CTM exploit IPs that have been banned. */
  unsigned long softban;
  unsigned long nickban;
  unsigned long badpasswd;
  unsigned long notags;
  unsigned long badmyinfo;
  unsigned long preloginevent;
  unsigned long loginevent;
  unsigned long logincached;
  unsigned long chatoverflow;	/* when a user oversteps his chat allowence */
  unsigned long chatfakenick;	/* when a user fakes his source nick */
  unsigned long chattoolong;
  unsigned long chatevent;
  unsigned long myinfooverflow;
  unsigned long myinfoevent;
  unsigned long searchoverflow;
  unsigned long searchcorrupt;
  unsigned long searchevent;
  unsigned long searchtoolong;
  unsigned long researchdrop;
  unsigned long researchmatch;
  unsigned long searchtth;
  unsigned long searchnormal;
  unsigned long sroverflow;
  unsigned long srevent;
  unsigned long srrobot;
  unsigned long srtoolong;
  unsigned long srfakesource;
  unsigned long srnodest;
  unsigned long ctmoverflow;
  unsigned long ctmbadtarget;
  unsigned long rctmoverflow;
  unsigned long rctmbadtarget;
  unsigned long rctmbadsource;
  unsigned long pmoverflow;
  unsigned long pmoutevent;
  unsigned long pmbadtarget;
  unsigned long pmbadsource;
  unsigned long pminevent;
  unsigned long botinfo;
  unsigned long cache_quit;
  unsigned long cache_myinfo;
  unsigned long cache_myinfoupdate;
  unsigned long cache_chat;
  unsigned long cache_asearch;
  unsigned long cache_psearch;
  unsigned long cache_messages;
  unsigned long cache_results;
} nmdc_stats_t;
extern nmdc_stats_t nmdc_stats;

/*
 *  This stuff includes and defines the protocol structure to be exported.
 */
#include "proto.h"
extern proto_t nmdc_proto;

#endif
