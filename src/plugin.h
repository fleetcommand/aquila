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

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include "config.h"
#include "buffer.h"
#include "cap.h"

#define	PLUGIN_EVENT_LOGIN	  0
#define	PLUGIN_EVENT_SEARCH	  1
#define	PLUGIN_EVENT_CHAT	  2
#define	PLUGIN_EVENT_PM_OUT	  3
#define PLUGIN_EVENT_PM_IN	  4
#define	PLUGIN_EVENT_LOGOUT	  5
#define	PLUGIN_EVENT_KICK	  6
#define	PLUGIN_EVENT_BAN	  7
#define PLUGIN_EVENT_INFOUPDATE   8
#define PLUGIN_EVENT_SR		  9
#define PLUGIN_EVENT_UPDATE	 10
#define PLUGIN_EVENT_REDIRECT    11
#define	PLUGIN_EVENT_PRELOGIN	 12
#define PLUGIN_EVENT_CACHEFLUSH  13
#define PLUGIN_EVENT_LOAD  	 14
#define PLUGIN_EVENT_SAVE  	 15
#define PLUGIN_EVENT_CONFIG	 16
#define PLUGIN_EVENT_DISCONNECT  17
#define PLUGIN_EVENT_ZOMBIE	 18

#define PLUGIN_EVENT_NUMBER	19


#define PLUGIN_NAME_LENGTH	64

#define PLUGIN_MAX_PLUGINS	32

#define PLUGIN_RETVAL_CONTINUE		0	/* continue processing */
#define PLUGIN_RETVAL_DROP		1	/* drop message.       */

/* keep these the same as the flags in proto.h */
#define PLUGIN_FLAG_HUBSEC               1
#define PLUGIN_FLAG_REGISTERED           2
#define PLUGIN_FLAG_ZOMBIE	         4

typedef struct plugin plugin_t;

typedef struct plugin_user {
  unsigned long long share;	/* share size */
  int active;			/* active? */
  unsigned int slots;		/* slots user have open */
  unsigned int hubs[3];		/* hubs user is in */
  unsigned long ipaddress;	/* ip address */
  unsigned char client[64];	/* client used */
  unsigned char versionstring[64];	/* client version */
  double version;
  unsigned int op;
  unsigned int flags;
  unsigned long rights;
  unsigned char nick[NICKLENGTH];
  unsigned long supports;
  
  void *private;
} plugin_user_t;

extern flag_t plugin_supports[];

/* callback */
typedef unsigned long (plugin_event_handler_t) (plugin_user_t *, void *, unsigned long event,
						buffer_t * token);

/* register plugin */
extern plugin_t *plugin_register (const char *name);
extern int plugin_unregister (plugin_t *);

/* request generic callback per event */
extern int plugin_request (plugin_t *, unsigned long event, plugin_event_handler_t *);
extern int plugin_ignore (plugin_t *, unsigned long event, plugin_event_handler_t *);

/* this stores or releases the private pointer of a plugin. */
extern int plugin_claim (plugin_t *, plugin_user_t *, void *);
extern int plugin_release (plugin_t *, plugin_user_t *);
extern void *plugin_retrieve (plugin_t *, plugin_user_t *);

/* this is used to create a "robot" user. all events for this user are passed to the callback. */
extern plugin_user_t *plugin_robot_add (unsigned char *name, unsigned char *description,
					plugin_event_handler_t *);
extern int plugin_robot_remove (plugin_user_t *);
extern plugin_event_handler_t *plugin_robot_set_handler (plugin_user_t * robot,
							 plugin_event_handler_t * handler);

/* stuff that can be done by a plugin */

extern int plugin_parse (plugin_user_t *, buffer_t *);

extern int plugin_user_next (plugin_user_t ** user);

/* user management */
extern plugin_user_t *plugin_user_find (unsigned char *name);
extern plugin_user_t *plugin_user_find_ip (plugin_user_t *last, unsigned long ip);
extern plugin_user_t *plugin_user_find_net (plugin_user_t *last, unsigned long ip, unsigned long net);
extern buffer_t * plugin_user_getmyinfo (plugin_user_t *user);

extern int plugin_user_kick (plugin_user_t * op, plugin_user_t * user, buffer_t * message);
extern int plugin_user_drop (plugin_user_t * user, buffer_t * message);
extern int plugin_user_banip (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
				       unsigned long period);
extern int plugin_user_banip_hard (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
					    unsigned long period);
extern int plugin_user_bannick (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
					 unsigned long period);
extern int plugin_user_ban (plugin_user_t * op, plugin_user_t * user, buffer_t * message,
				     unsigned long period);
extern int plugin_user_unban (plugin_user_t * user);

extern int plugin_user_raw (plugin_user_t * tgt, buffer_t * message);
extern int plugin_user_raw_all (buffer_t * message);

extern int plugin_user_say (plugin_user_t * src, buffer_t * message);
extern int plugin_user_sayto (plugin_user_t * src, plugin_user_t * target,
				       buffer_t * message,int direct);
extern int plugin_user_priv (plugin_user_t * src, plugin_user_t * target,
				      plugin_user_t * source, buffer_t * message, int direct);
extern int plugin_user_printf (plugin_user_t * user, const char *format, ...);
extern int plugin_user_redirect (plugin_user_t * user, buffer_t * message);
extern int plugin_user_forcemove (plugin_user_t * user, unsigned char *destination,
					   buffer_t * message);
extern int plugin_ban (plugin_user_t * op, unsigned char *nick, unsigned long ip, unsigned long netmask, buffer_t * message, unsigned long period);
extern int plugin_ban_ip (plugin_user_t * op, unsigned long ip, unsigned long netmask, buffer_t * message, unsigned long period);
extern int plugin_ban_ip_hard (plugin_user_t * op, unsigned long ip, unsigned long netmask, buffer_t * message, unsigned long period);
extern int plugin_ban_nick (plugin_user_t * op, unsigned char *nick, buffer_t * message, unsigned long period);
extern int plugin_unban (unsigned char *nick);
extern int plugin_unban_ip (unsigned long ip, unsigned long netmask);
extern int plugin_unban_ip_hard (unsigned long ip, unsigned long netmask);
extern int plugin_unban_nick (unsigned char *nick);
extern int plugin_user_zombie (plugin_user_t * user);
extern int plugin_user_unzombie (plugin_user_t * user);

extern int plugin_user_findnickban (buffer_t * buf, unsigned char *nick);
extern int plugin_user_findipban (buffer_t * buf, unsigned long ip);
extern int plugin_user_findiphardban (buffer_t * buf, unsigned long ip);
extern int plugin_banlist (buffer_t *output);
extern int plugin_hardbanlist (buffer_t * output);

extern unsigned long long plugin_right_create (unsigned char *name, unsigned char *right);
extern int plugin_right_destroy (unsigned char *name);

extern int plugin_report (buffer_t * message);
extern int plugin_perror (unsigned char *format, ...);
extern int plugin_config_load ();
extern int plugin_config_save (buffer_t * output);

extern unsigned long plugin_user_event (plugin_user_t * user, unsigned long event, void *token);

extern int plugin_user_setrights (plugin_user_t *user, unsigned long long cap, unsigned long long ncap);

#endif
