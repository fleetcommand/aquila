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
#ifndef _NMDC_NICKLISTCACHE_H_
#define _NMDC_NICKLISTCACHE_H_

/* define extra size of nicklist infobuffer. when this extra space is full, 
 * nicklist is rebuild. keep this relatively small to reduce bw overhead.
 * the actual space will grow with the number of users logged in.
 * the number is used to shift the size.
 *  3 corresponds to a 12.5 % extra size before rebuild.
 */

#define NICKLISTCACHE_SPARE	3

typedef struct {
  string_list_t messages;
  unsigned long length;
  leaky_bucket_t timer;
  leaky_bucket_type_t timertype;
} cache_element_t;

#define cache_queue(element, user, buffer)	{string_list_add (&(element).messages , user, buffer); (element).length += bf_size (buffer);}
//#define cache_count(element, user, buffer)	{(element).messages.count++; (element).messages.size += bf_size (buffer); (element).length += bf_size (buffer);}
#define cache_count(element, user)		{ if (cache.element.messages.count < ((nmdc_user_t *) user->pdata)->element.messages.count) cache.element.messages.count = ((nmdc_user_t *) user->pdata)->element.messages.count; if (cache.element.messages.size < ((nmdc_user_t *) user->pdata)->element.messages.size) cache.element.messages.size = ((nmdc_user_t *) user->pdata)->element.messages.size; if (cache.element.length < ((nmdc_user_t *) user->pdata)->element.length) cache.element.length = ((nmdc_user_t *) user->pdata)->element.length ;}
#define cache_purge(element, user)		{string_list_entry_t *entry = string_list_find (&(element).messages, user); while (entry) { (element).length -= bf_size (entry->data); string_list_del (&(element).messages, entry); entry = string_list_find (&(element).messages, user); };}
#define cache_clear(element)			{string_list_clear (&(element).messages); (element).length = 0;}
#define cache_clearcount(element)		{ element.messages.count = 0; (element).length = 0;}

typedef struct {
  /*
   *    Normal communication caching
   */
  cache_element_t chat;		/* chatmessages */
  cache_element_t myinfo;	/* my info messages */
  cache_element_t myinfoupdate;	/* my info update messages */
  cache_element_t myinfoupdateop;	/* my info update messages for ops. not shortened and immediate */
  cache_element_t asearch;	/* active search list */
  cache_element_t psearch;	/* passive search list */
  cache_element_t aresearch;	/* active search list */
  cache_element_t presearch;	/* passive search list */
  cache_element_t results;	/* results */
  cache_element_t privatemessages;	/* privatemessages */

  /*
   *
   */
  unsigned long ZpipeSupporters;
  unsigned long ZlineSupporters;

  /*
   *  nicklist caching
   */
  unsigned long usercount;
  unsigned long lastrebuild;
  unsigned long needrebuild;
  buffer_t *nicklist;
  buffer_t *oplist;
  buffer_t *infolist;
  buffer_t *hellolist;
#ifdef ZLINES
  buffer_t *infolistzline;
  buffer_t *nicklistzline;
  buffer_t *infolistzpipe;
  buffer_t *nicklistzpipe;
#endif
  buffer_t *infolistupdate;

  unsigned long length_estimate;
  unsigned long length_estimate_op;
  unsigned long length_estimate_info;
  
  unsigned long nicklist_length;
  unsigned long oplist_length;
  unsigned long infolist_length;
  unsigned long hellolist_length;
#ifdef ZLINES
  unsigned long infolistzline_length;
  unsigned long nicklistzline_length;
  unsigned long infolistzpipe_length;
  unsigned long nicklistzpipe_length;
#endif
  unsigned long infolistupdate_length;

  unsigned long nicklist_count;
  unsigned long oplist_count;
  unsigned long infolist_count;
  unsigned long hellolist_count;
#ifdef ZLINES
  unsigned long infolistzline_count;
  unsigned long nicklistzline_count;
  unsigned long infolistzpipe_count;
  unsigned long nicklistzpipe_count;
#endif
  unsigned long infolistupdate_bytes;
  
} cache_t;

extern int nicklistcache_adduser (user_t * u);
extern int nicklistcache_updateuser (user_t *old, user_t * new);
extern int nicklistcache_updatemyinfo (buffer_t *old, buffer_t * new);
extern int nicklistcache_deluser (user_t * u);
//extern int nicklistcache_rebuild (struct timeval now);
extern int nicklistcache_sendnicklist (user_t * target);
extern int nicklistcache_sendoplist (user_t * target);

#ifdef DEBUG

#  define NICKLISTCACHE_VERIFY	nicklistcache_verify()
  extern void nicklistcache_verify ();

#else
#  define NICKLISTCACHE_VERIFY
#endif

#endif
