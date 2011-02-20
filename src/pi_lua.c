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
 *  Thanks to Tomas "ZeXx86" Jedrzejek (admin@infern0.tk) for original implementation
 */

#include "plugin_int.h"
#include <sys/types.h>
#include <string.h>
#include <assert.h>

#ifndef USE_WINDOWS
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#else
#  include "sys_windows.h"
#endif

#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <math.h>

#include "utils.h"
#include "commands.h"
#include "user.h"
#include "cap.h"
#include "config.h"

extern account_t *accounts;

const unsigned char *pi_lua_eventnames[] = {
  "EventLogin",
  "EventSearch",
  "EventChat",
  "EventPMOut",
  "EventPMIn",
  "EventLogout",
  "EventKick",
  "EventBan",
  "EventInfoUpdate",
  "EventSearchResult",
  "EventUpdate",
  "EventRedirect",
  "EventPreLogin",
  "EventCacheFlush",
  "EventLoad",
  "EventSave",
  "EventConfig",
  "EventDisconnect",
  "EventZombie",
  NULL
};


/* this is a dirty trick so we can find the user pointer even before the user is hashed... 
 *  THIS WILL BACKFIRE WITH MULTITHREADING!
 */
plugin_user_t *pi_lua_eventuser;

unsigned char *pi_lua_savefile;

plugin_t *plugin_lua = NULL;

/* 
 * robot contexts
 */

typedef struct lua_robot_context {
  struct lua_robot_context *next, *prev;

  plugin_user_t *robot;
  unsigned char *handler;
} lua_robot_context_t;

/*
 * script contexts
 */

unsigned int lua_ctx_cnt, lua_ctx_peak;
typedef struct lua_context {
  struct lua_context *next, *prev;

  lua_State *l;
  unsigned char *name;
  unsigned long long eventmap;

  lua_robot_context_t robots;
} lua_context_t;

lua_context_t lua_list;


unsigned int pi_lua_close (unsigned char *name);

unsigned long long pi_lua_eventmap;


unsigned long pi_lua_event_handler (plugin_user_t * user, buffer_t * output,
				    unsigned long event, buffer_t * token);


#define PLUGIN_USER_FIND(arg) 	( (pi_lua_eventuser && !strcmp(arg, pi_lua_eventuser->nick)) ? pi_lua_eventuser : plugin_user_find (arg) )

#define PUSH_TABLE_ENTRY(ctx, name, entry)  { lua_pushstring (ctx, name); lua_pushstring (ctx, entry); lua_settable(ctx, -3); }
#define PUSH_TABLE_ENTRY_NUMBER(ctx, name, entry)  { lua_pushstring (ctx, name); lua_pushnumber (ctx, entry); lua_settable(ctx, -3); }


/******************************* LUA INTERFACE *******************************************/

/******************************************************************************************
 *   Utilities
 */

unsigned int parserights (unsigned char *caps, unsigned long long *cap, unsigned long long *ncap)
{
  unsigned int j;
  unsigned char *c, *d, *tmp;

  tmp = strdup (caps);
  c = strtok (tmp, " ,");
  while (c) {
    d = c;
    if ((*d == '-') || (*d == '+'))
      d++;
    for (j = 0; Capabilities[j].name; j++) {
      if (!Capabilities[j].flag)
	continue;
      if (!strcasecmp (Capabilities[j].name, d)) {
	if (c[0] != '-') {
	  *cap |= Capabilities[j].flag;
	  *ncap &= ~Capabilities[j].flag;
	} else {
	  *ncap |= Capabilities[j].flag;
	  *cap &= ~Capabilities[j].flag;
	}
	break;
      }
    };
    c = strtok (NULL, " ,");
  }
  free (tmp);

  return 0;
}

/******************************************************************************************
 *  LUA Function Configuration handling
 */

int pi_lua_getconfig (lua_State * lua)
{
  config_element_t *elem;

  unsigned char *name = (unsigned char *) luaL_checkstring (lua, 1);

  elem = config_find (name);
  if (!elem) {
    /* push error message */
    lua_pushstring (lua, __ ("Unknown config value."));
    /* flag error, this function never returns. */
    lua_error (lua);
  }

  switch (elem->type) {
    case CFG_ELEM_LONG:
      lua_pushnumber (lua, *elem->val.v_long);
      break;
    case CFG_ELEM_ULONG:
      lua_pushnumber (lua, *elem->val.v_ulong);
      break;
    case CFG_ELEM_ULONGLONG:
      lua_pushnumber (lua, *elem->val.v_ulonglong);
      break;
    case CFG_ELEM_INT:
      lua_pushnumber (lua, *elem->val.v_int);
      break;
    case CFG_ELEM_UINT:
      lua_pushnumber (lua, *elem->val.v_uint);
      break;
    case CFG_ELEM_DOUBLE:
      lua_pushnumber (lua, *elem->val.v_double);
      break;

    case CFG_ELEM_STRING:
      lua_pushstring (lua, *elem->val.v_string);
      break;

    case CFG_ELEM_IP:
      {
	struct in_addr in;

	in.s_addr = *elem->val.v_ip;
	lua_pushstring (lua, inet_ntoa (in));
	break;
      }
    case CFG_ELEM_BYTESIZE:
      lua_pushstring (lua, format_size (*elem->val.v_ulonglong));
      break;

    case CFG_ELEM_MEMSIZE:
      lua_pushstring (lua, format_size (*elem->val.v_ulong));
      break;

    case CFG_ELEM_CAP:
      {
	buffer_t *b = bf_alloc (1024);

	flags_print ((Capabilities + CAP_PRINT_OFFSET), b, *elem->val.v_ulong);

	lua_pushstring (lua, b->s);

	bf_free (b);
      }
      break;
    case CFG_ELEM_PTR:
      lua_pushstring (lua, __ ("Element Type not supported."));
      lua_error (lua);
      break;
  };

  return 1;
}

int pi_lua_setconfig (lua_State * lua)
{
  config_element_t *elem = NULL;

  unsigned char *name = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *value = (unsigned char *) luaL_checkstring (lua, 2);

  elem = config_find (name);
  if (!elem) {
    /* push error message */
    lua_pushstring (lua, __ ("Unknown config value."));
    /* flag error, this function never returns. */
    lua_error (lua);
  }

  switch (elem->type) {
    case CFG_ELEM_LONG:
      sscanf (value, "%ld", elem->val.v_long);
      break;
    case CFG_ELEM_ULONG:
      sscanf (value, "%lu", elem->val.v_ulong);
      break;
    case CFG_ELEM_ULONGLONG:
#ifndef USE_WINDOWS
      sscanf (value, "%Lu", elem->val.v_ulonglong);
#else
      sscanf (value, "%I64u", elem->val.v_ulonglong);
#endif
      break;
    case CFG_ELEM_INT:
      sscanf (value, "%d", elem->val.v_int);
      break;
    case CFG_ELEM_UINT:
      sscanf (value, "%u", elem->val.v_uint);
      break;
    case CFG_ELEM_DOUBLE:
      sscanf (value, "%lf", elem->val.v_double);
      break;
    case CFG_ELEM_STRING:
      if (*elem->val.v_string)
	free (*elem->val.v_string);
      *elem->val.v_string = strdup (value);
      break;
    case CFG_ELEM_IP:
      {
	struct in_addr ia;

	if (!inet_aton (value, &ia)) {
	  lua_pushstring (lua, __ ("Not a valid IP address.\n"));
	  lua_error (lua);
	}
	*elem->val.v_ip = ia.s_addr;
      }
      break;
    case CFG_ELEM_BYTESIZE:
      *elem->val.v_ulonglong = parse_size (value);
      break;

    case CFG_ELEM_PTR:
      {
	unsigned long long caps = 0, ncaps = 0;

	parserights (value, &caps, &ncaps);

	*elem->val.v_ulong = caps;
      }
      break;
    case CFG_ELEM_CAP:
    default:
      lua_pushstring (lua, __ ("Element Type not supported."));
      lua_error (lua);
  }

  plugin_user_event (NULL, PLUGIN_EVENT_CONFIG, elem);

  return 1;
}


/******************************************************************************************
 *  LUA Function IO Handling
 */
extern long users_total;
int pi_lua_getuserstotal (lua_State * lua)
{
#ifdef PLUGIN_USER
  lua_pushnumber (lua, users_total);
#else
  lua_pushnumber (lua, 0);
#endif

  return 1;
}

int pi_lua_getuserip (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    struct in_addr in;

    in.s_addr = user->ipaddress;
    lua_pushstring (lua, inet_ntoa (in));
  }

  return 1;
}

int pi_lua_getuserclient (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushstring (lua, user->client);
  }

  return 1;
}

int pi_lua_getuserclientversion (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushstring (lua, user->versionstring);
  }

  return 1;
}

int pi_lua_getusershare (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushstring (lua, format_size (user->share));
  }

  return 1;
}

int pi_lua_getusersharenum (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushnumber (lua, user->share);
  }

  return 1;
}

int pi_lua_getuserslots (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushnumber (lua, user->slots);
  }

  return 1;
}

int pi_lua_getuserhubs (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
    lua_pushnil (lua);
    lua_pushnil (lua);
  } else {
    lua_pushnumber (lua, user->hubs[0]);
    lua_pushnumber (lua, user->hubs[1]);
    lua_pushnumber (lua, user->hubs[2]);
  }

  return 3;
}


int pi_lua_userisop (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushboolean (lua, user->op);
  }

  return 1;
}

int pi_lua_userisonline (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  lua_pushboolean (lua, (user != NULL));

  return 1;
}

int pi_lua_userisactive (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushboolean (lua, user->active);
  }

  return 1;
}

int pi_lua_userisregistered (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushboolean (lua, (user->flags & PLUGIN_FLAG_REGISTERED));
  }

  return 1;
}

int pi_lua_useriszombie (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    lua_pushboolean (lua, (user->flags & PLUGIN_FLAG_ZOMBIE));
  }

  return 1;
}


int pi_lua_getuserrights (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;
  buffer_t *b;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    b = bf_alloc (10240);
    flags_print ((Capabilities + CAP_PRINT_OFFSET), b, user->rights);
    lua_pushlstring (lua, b->s, bf_used (b));
    bf_free (b);
  }

  return 1;
}

int pi_lua_getusergroup (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;
  account_t *acc;

  user = PLUGIN_USER_FIND (nick);
  if (!user)
    goto leave;

  if (!(user->flags & PLUGIN_FLAG_REGISTERED))
    goto leave;

  acc = account_find (user->nick);
  if (!acc)
    goto leave;

  lua_pushstring (lua, acc->classp->name);

  return 1;

leave:
  lua_pushnil (lua);

  return 1;
}

int pi_lua_getusersupports (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;
  buffer_t *b;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    b = bf_alloc (10240);
    flags_print ((plugin_supports), b, user->supports);
    lua_pushlstring (lua, b->s, bf_used (b));
    bf_free (b);
  }

  return 1;
}


int pi_lua_getusermyinfo (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *user;
  buffer_t *b;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    b = plugin_user_getmyinfo (user);
    lua_pushlstring (lua, b->s, bf_used (b));
  }

  return 1;
}

int pi_lua_setuserrights (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *right = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned long long cap = 0, ncap = 0;
  plugin_user_t *user;

  user = PLUGIN_USER_FIND (nick);

  if (!user) {
    lua_pushnil (lua);
  } else {
    parserights (right, &cap, &ncap);
    plugin_user_setrights (user, cap, ncap);
  }

  return 1;
}


/******************************************************************************************
 *  LUA Functions User handling
 */

int pi_lua_user_kick (lua_State * lua)
{
  buffer_t *b;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 2);
  plugin_user_t *u;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_user_kick (NULL, u, b);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

int pi_lua_user_drop (lua_State * lua)
{
  buffer_t *b;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 2);
  plugin_user_t *u;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_user_drop (u, b);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

int pi_lua_user_ban (lua_State * lua)
{
  buffer_t *b;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *periodstring = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);
  plugin_user_t *u;
  unsigned long period;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  period = time_parse (periodstring);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_user_ban (NULL, u, b, period);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

int pi_lua_user_bannick (lua_State * lua)
{
  buffer_t *b;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *periodstring = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);
  plugin_user_t *u;
  unsigned long period;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  period = time_parse (periodstring);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_user_bannick (NULL, u, b, period);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

int pi_lua_user_banip (lua_State * lua)
{
  buffer_t *b;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *periodstring = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);
  plugin_user_t *u;
  unsigned long period;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  period = time_parse (periodstring);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_user_banip (NULL, u, b, period);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

int pi_lua_user_banip_hard (lua_State * lua)
{
  buffer_t *b;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *periodstring = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);
  plugin_user_t *u;
  unsigned long period;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  period = time_parse (periodstring);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_user_banip_hard (NULL, u, b, period);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}


int pi_lua_banip (lua_State * lua)
{
  buffer_t *b;
  unsigned char *ip = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *periodstring = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);
  unsigned long period;
  struct in_addr ia, netmask;

  period = time_parse (periodstring);


  if (!parse_ip (ip, &ia, &netmask)) {
    lua_pushstring (lua, __ ("Not a valid IP address.\n"));
    lua_error (lua);
  }

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_ban_ip (NULL, ia.s_addr, netmask.s_addr, b, period);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

int pi_lua_banip_hard (lua_State * lua)
{
  buffer_t *b;
  unsigned char *ip = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *periodstring = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);
  unsigned long period;
  struct in_addr ia, netmask;

  period = time_parse (periodstring);


  if (!parse_ip (ip, &ia, &netmask)) {
    lua_pushstring (lua, __ ("Not a valid IP address.\n"));
    lua_error (lua);
  }

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_ban_ip_hard (NULL, ia.s_addr, netmask.s_addr, b, period);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

int pi_lua_unban (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);

  lua_pushboolean (lua, plugin_unban (nick));

  return 1;
}

int pi_lua_unbannick (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);

  lua_pushboolean (lua, plugin_unban_nick (nick));

  return 1;
}

int pi_lua_unbanip (lua_State * lua)
{
  unsigned char *ip = (unsigned char *) luaL_checkstring (lua, 1);
  struct in_addr ia, netmask;

  if (!parse_ip (ip, &ia, &netmask)) {
    lua_pushstring (lua, __ ("Not a valid IP address.\n"));
    lua_error (lua);
  }

  lua_pushboolean (lua, plugin_unban_ip (ia.s_addr, netmask.s_addr));

  return 1;
}

int pi_lua_unbanip_hard (lua_State * lua)
{
  unsigned char *ip = (unsigned char *) luaL_checkstring (lua, 1);
  struct in_addr ia, netmask;

  if (!parse_ip (ip, &ia, &netmask)) {
    lua_pushstring (lua, __ ("Not a valid IP address.\n"));
    lua_error (lua);
  }

  lua_pushboolean (lua, plugin_unban_ip_hard (ia.s_addr, netmask.s_addr));

  return 1;
}

int pi_lua_user_zombie (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *u;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  lua_pushboolean (lua, plugin_user_zombie (u));

  return 1;
}

int pi_lua_user_unzombie (lua_State * lua)
{
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *u;

  u = plugin_user_find (nick);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  lua_pushboolean (lua, plugin_user_unzombie (u));

  return 1;
}

int pi_lua_findnickban (lua_State * lua)
{
  buffer_t *b;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);

  b = bf_alloc (10240);

  if (plugin_user_findnickban (b, nick)) {
    lua_pushstring (lua, b->s);
  } else {
    lua_pushnil (lua);
  }

  bf_free (b);

  return 1;
}

int pi_lua_findipban (lua_State * lua)
{
  buffer_t *b;
  unsigned char *ip = (unsigned char *) luaL_checkstring (lua, 1);
  struct in_addr ia;

  if (!inet_aton (ip, &ia)) {
    lua_pushstring (lua, __ ("Not a valid IP address.\n"));
    lua_error (lua);
  }

  b = bf_alloc (10240);

  if (plugin_user_findipban (b, ia.s_addr)) {
    lua_pushstring (lua, b->s);
  } else {
    lua_pushnil (lua);
  }

  bf_free (b);

  return 1;
}

int pi_lua_report (lua_State * lua)
{
  buffer_t *b;
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 1);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  plugin_report (b);

  bf_free (b);

  lua_pushboolean (lua, 1);

  return 1;
}

/******************************************************************************************
 *  LUA message functions
 */

int pi_lua_sendtoall (lua_State * lua)
{
  buffer_t *b;
  plugin_user_t *u;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 2);

  u = plugin_user_find (nick);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  lua_pushboolean (lua, plugin_user_say (u, b));

  bf_free (b);

  return 1;
}

int pi_lua_sendtonick (lua_State * lua)
{
  buffer_t *b;
  plugin_user_t *s, *d;
  unsigned char *src = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *dest = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);

  s = plugin_user_find (src);
  /* s can be NULL, wil become hubsec */

  d = PLUGIN_USER_FIND (dest);
  if (!d) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  lua_pushboolean (lua, plugin_user_sayto (s, d, b, 0));

  bf_free (b);

  return 1;
}

int pi_lua_sendpmtoall (lua_State * lua)
{
  unsigned int i;
  buffer_t *b;
  plugin_user_t *tgt = NULL, *u, *prev = NULL;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 2);

  u = plugin_user_find (nick);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  /* send to all users */
  i = 0;
  prev = NULL;
  while (plugin_user_next (&tgt)) {
    /* weird is i set direct to 1 it doesn't work. */
    prev = tgt;
    if (plugin_user_priv (u, tgt, u, b, 0) < 0) {
      tgt = prev;
    } else {
      i++;
    }
  }
  lua_pushnumber (lua, i);

  bf_free (b);

  return 1;
}

int pi_lua_sendpmtonick (lua_State * lua)
{
  buffer_t *b;
  plugin_user_t *s, *d;
  unsigned char *src = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *dest = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);

  s = plugin_user_find (src);
  /* s can be NULL, wil become hubsec */

  d = PLUGIN_USER_FIND (dest);
  if (!d) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  lua_pushboolean (lua, plugin_user_priv (s, d, s, b, 1));

  bf_free (b);

  return 1;
}

int pi_lua_sendtorights (lua_State * lua)
{
  unsigned int i;
  buffer_t *b;
  plugin_user_t *tgt = NULL, *u, *prev = NULL;
  unsigned long long cap = 0, ncap = 0;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);

  u = plugin_user_find (nick);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  parserights (rights, &cap, &ncap);

  /* send to all users */
  i = 0;
  prev = NULL;
  while (plugin_user_next (&tgt)) {
    prev = tgt;
    if (((tgt->rights & cap) != cap) || ((tgt->rights & ncap) != 0))
      continue;
    if (plugin_user_sayto (u, tgt, b, 0) < 0) {
      tgt = prev;
    } else {
      i++;
    }
  }
  lua_pushnumber (lua, i);

  bf_free (b);

  return 1;
}

int pi_lua_rawtorights (lua_State * lua)
{
  unsigned int i;
  buffer_t *b;
  plugin_user_t *tgt = NULL, *prev = NULL;
  unsigned long long cap = 0, ncap = 0;
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 2);

  b = bf_alloc (10240);

  bf_printf (b, "%s", message);

  parserights (rights, &cap, &ncap);

  /* send to all users */
  i = 0;
  prev = NULL;
  while (plugin_user_next (&tgt)) {
    prev = tgt;
    if (((tgt->rights & cap) != cap) || ((tgt->rights & ncap) != 0))
      continue;
    if (plugin_user_raw (tgt, b) < 0) {
      tgt = prev;
    } else {
      i++;
    }
  }
  lua_pushnumber (lua, i);

  bf_free (b);

  return 1;
}

int pi_lua_sendpmtorights (lua_State * lua)
{
  unsigned int i;
  buffer_t *b;
  plugin_user_t *tgt = NULL, *u, *prev = NULL;
  unsigned long long cap = 0, ncap = 0;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 3);

  u = plugin_user_find (nick);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  parserights (rights, &cap, &ncap);

  /* send to all users */
  i = 0;
  prev = NULL;
  while (plugin_user_next (&tgt)) {
    prev = tgt;
    if (((tgt->rights & cap) != cap) || ((tgt->rights & ncap) != 0))
      continue;
    if (plugin_user_priv (u, tgt, u, b, 0) < 0) {
      tgt = prev;
    } else {
      i++;
    }
  }
  lua_pushnumber (lua, i);

  bf_free (b);

  return 1;
}

int pi_lua_rawtonick (lua_State * lua)
{
  buffer_t *b;
  plugin_user_t *d;
  unsigned char *dest = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 2);

  d = PLUGIN_USER_FIND (dest);
  if (!d) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  lua_pushboolean (lua, plugin_user_raw (d, b));

  bf_free (b);

  return 1;
}

int pi_lua_rawtoall (lua_State * lua)
{
  buffer_t *b;
  unsigned char *message = (unsigned char *) luaL_checkstring (lua, 1);

  b = bf_alloc (10240);
  bf_printf (b, "%s", message);

  lua_pushboolean (lua, plugin_user_raw_all (b));

  bf_free (b);

  return 1;
}

/******************************************************************************************
 *  LUA Account Command Handling
 */

int pi_lua_account_create (lua_State * lua)
{
  unsigned int retval = 0;
  lua_context_t *ctx;
  account_type_t *grp;
  account_t *acc;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *group = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *op = NULL;

  if (lua_gettop (lua) > 2)
    op = (unsigned char *) luaL_checkstring (lua, 3);

  grp = account_type_find (group);
  if (!grp)
    goto leave;

  if (!op) {
    for (ctx = lua_list.next; (ctx != &lua_list); ctx = ctx->next)
      if (ctx->l == lua)
	break;

    assert (ctx != &lua_list);
    op = ctx->name;
  }

  acc = account_add (grp, op, nick);
  if (!acc)
    goto leave;

  retval = 1;
leave:
  lua_pushboolean (lua, retval);
  return 1;
}

int pi_lua_account_delete (lua_State * lua)
{
  unsigned int retval = 0;
  account_t *acc;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);

  acc = account_find (nick);
  if (!acc)
    goto leave;

  account_del (acc);

  retval = 1;
leave:
  lua_pushboolean (lua, retval);
  return 1;
}

int pi_lua_account_passwd (lua_State * lua)
{
  unsigned int retval = 0;
  account_t *acc;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *passwd = (unsigned char *) luaL_checkstring (lua, 2);

  acc = account_find (nick);
  if (!acc)
    goto leave;

  account_pwd_set (acc, passwd);

  retval = 1;
leave:
  lua_pushboolean (lua, retval);
  return 1;
}

int pi_lua_account_pwgen (lua_State * lua)
{
  unsigned int i;
  account_t *acc;
  unsigned char passwd[64];

  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned int pwlen = luaL_checknumber (lua, 2);

  if ((pwlen < 4) || (pwlen > 50))
    pwlen = 12;

  passwd[0] = 0;
  acc = account_find (nick);
  if (!acc)
    goto leave;

  for (i = 0; i < pwlen; i++) {
    passwd[i] = (33 + (random () % 90));
  }
  passwd[i] = '\0';

  account_pwd_set (acc, passwd);

leave:
  lua_pushstring (lua, passwd);
  return 1;
}

int pi_lua_account_find (lua_State * lua)
{
  account_t *acc;
  buffer_t *b;
  struct in_addr ia;

  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);

  acc = account_find (nick);
  if (!acc)
    goto leave;

  lua_newtable (lua);

  PUSH_TABLE_ENTRY (lua, "nick", acc->nick);

  b = bf_alloc (10240);
  flags_print ((Capabilities + CAP_PRINT_OFFSET), b, acc->rights | acc->classp->rights);
  PUSH_TABLE_ENTRY (lua, "rights", b->s);
  bf_free (b);

  PUSH_TABLE_ENTRY (lua, "group", acc->classp->name);
  PUSH_TABLE_ENTRY (lua, "op", acc->op);
  PUSH_TABLE_ENTRY_NUMBER (lua, "registered", acc->regged);
  PUSH_TABLE_ENTRY_NUMBER (lua, "lastlogin", acc->lastlogin);
  ia.s_addr = acc->lastip;
  PUSH_TABLE_ENTRY (lua, "lastip", inet_ntoa (ia));

  return 1;
leave:
  lua_pushnil (lua);
  return 1;
}

int pi_lua_account_list (lua_State * lua)
{
  account_t *account;
  //buffer_t *b;
  //struct in_addr ia;
  //unsigned int i;
  
  lua_newtable(lua);
  
  for (account = accounts; account; account = account->next ) {
    PUSH_TABLE_ENTRY_NUMBER(lua, account->nick, 1);
  };
/*  
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);

  acc = account_find (nick);
  if (!acc)
    goto leave;

  PUSH_TABLE_ENTRY (lua, "nick", acc->nick);

  b = bf_alloc (10240);
  flags_print ((Capabilities + CAP_PRINT_OFFSET), b, acc->rights | acc->classp->rights);
  PUSH_TABLE_ENTRY (lua, "rights", b->s);
  bf_free (b);

  PUSH_TABLE_ENTRY (lua, "group", acc->classp->name);
  PUSH_TABLE_ENTRY (lua, "op", acc->op);
  PUSH_TABLE_ENTRY_NUMBER (lua, "registered", acc->regged);
  PUSH_TABLE_ENTRY_NUMBER (lua, "lastlogin", acc->lastlogin);
  ia.s_addr = acc->lastip;
  PUSH_TABLE_ENTRY (lua, "lastip", inet_ntoa (ia));
*/
  return 1;
}

int pi_lua_account_setrights (lua_State * lua)
{
  account_t *acc;
  unsigned long retval = 0;
  unsigned long long caps = 0, ncaps = 0;

  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 2);

  acc = account_find (nick);
  if (!acc)
    goto leave;

  parserights (rights, &caps, &ncaps);

  acc->rights |= caps;
  acc->rights &= ~ncaps;

  retval = 1;
leave:
  lua_pushboolean (lua, retval);
  return 1;
}

int pi_lua_account_lastlogin (lua_State * lua)
{
  account_t *acc;

  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);

  acc = account_find (nick);
  if (!acc)
    goto leave;

  lua_pushnumber (lua, acc->lastlogin);

  return 1;
leave:
  lua_pushnil (lua);
  return 1;
}

int pi_lua_group_create (lua_State * lua)
{
  unsigned int retval = 0;
  unsigned long long caps = 0, ncaps = 0;
  account_type_t *grp;
  unsigned char *group = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 2);

  parserights (rights, &caps, &ncaps);

  grp = account_type_add (group, caps);
  if (!grp)
    goto leave;

  retval = 1;
leave:
  lua_pushboolean (lua, retval);
  return 1;
}

int pi_lua_group_setrights (lua_State * lua)
{
  account_type_t *grp;
  unsigned long retval = 0;
  unsigned long long caps = 0, ncaps = 0;

  unsigned char *group = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 2);

  grp = account_type_find (group);
  if (!grp)
    goto leave;

  parserights (rights, &caps, &ncaps);

  grp->rights |= caps;
  grp->rights &= ~ncaps;

  retval = 1;
leave:
  lua_pushboolean (lua, retval);
  return 1;
}


int pi_lua_group_inuse (lua_State * lua)
{
  unsigned int retval = 0;
  account_type_t *grp;

  unsigned char *group = (unsigned char *) luaL_checkstring (lua, 1);

  grp = account_type_find (group);
  if (!grp)
    goto leave;

  retval = (grp->refcnt != 0);

leave:
  lua_pushboolean (lua, retval);
  return 1;
}

int pi_lua_group_delete (lua_State * lua)
{
  unsigned int retval = 0;
  account_type_t *grp;

  unsigned char *group = (unsigned char *) luaL_checkstring (lua, 1);

  grp = account_type_find (group);
  if (!grp)
    goto leave;

  if (grp->refcnt)
    goto leave;

  account_type_del (grp);
  retval = 1;
leave:
  lua_pushboolean (lua, retval);
  return 1;
}

int pi_lua_group_find (lua_State * lua)
{
  account_type_t *acc;
  buffer_t *b;

  unsigned char *name = (unsigned char *) luaL_checkstring (lua, 1);

  acc = account_type_find (name);
  if (!acc)
    goto leave;

  lua_newtable (lua);

  PUSH_TABLE_ENTRY (lua, "name", acc->name);

  b = bf_alloc (10240);
  flags_print ((Capabilities + CAP_PRINT_OFFSET), b, acc->rights);
  PUSH_TABLE_ENTRY (lua, "rights", b->s);
  bf_free (b);

  return 1;
leave:
  lua_pushnil (lua);
  return 1;
}

/******************************************************************************************
 *  LUA Functions Bot handling
 */

unsigned long pi_lua_robot_event_handler (plugin_user_t * user, void *dummy,
					  unsigned long event, buffer_t * token)
{
  int result = PLUGIN_RETVAL_CONTINUE;
  lua_context_t *ctx;
  lua_robot_context_t *robot = NULL;

  /* weird, but we can't handle this. */
  if (!user)
    return result;

  for (ctx = lua_list.next; (ctx != &lua_list); ctx = ctx->next) {
    for (robot = ctx->robots.next; robot != &ctx->robots; robot = robot->next) {
      if (robot->robot == user)
	break;
    }
    if (robot->robot == user)
      break;
  }
  ASSERT (ctx != &lua_list);
  ASSERT (robot != &ctx->robots);

  /* clear stack */
  lua_settop (ctx->l, 0);

  /* specify function to call */
  /* lua 5.1 
     lua_getfield (ctx->l, LUA_GLOBALSINDEX, command);
   */

  /* lua 5.0 */
  lua_pushstring (ctx->l, robot->handler);
  lua_gettable (ctx->l, LUA_GLOBALSINDEX);

  /* push arguments */
  lua_pushstring (ctx->l, (user ? user->nick : (unsigned char *) ""));
  if (event == PLUGIN_EVENT_CONFIG) {
    config_element_t *elem = (config_element_t *) token;

    lua_pushstring (ctx->l, (elem ? elem->name : (unsigned char *) ""));
  } else {
    lua_pushstring (ctx->l, (token ? token->s : (unsigned char *) ""));
  }
  lua_pushstring (ctx->l, pi_lua_eventnames[event]);

  /* call funtion. */
  result = lua_pcall (ctx->l, 3, 1, 0);
  if (result) {
    unsigned char *error = (unsigned char *) luaL_checkstring (ctx->l, 1);
    buffer_t *buf;

    DPRINTF ("LUA ERROR: %s\n", error);

    buf = bf_alloc (32 + strlen (error) + strlen (ctx->name));

    bf_printf (buf, _("LUA ERROR ('%s'): %s\n"), ctx->name, error);

    plugin_report (buf);

    bf_free (buf);

    /* do not drop message if handler failed */
    result = PLUGIN_RETVAL_CONTINUE;
  }

  /* retrieve return value */
  if (lua_isboolean (ctx->l, -1)) {
    result = lua_toboolean (ctx->l, -1);
    lua_remove (ctx->l, -1);
  }

  return result;
}

int pi_lua_addbot (lua_State * lua)
{
  plugin_user_t *u;
  lua_context_t *ctx;
  lua_robot_context_t *robot;

  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *description = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *function = (unsigned char *) luaL_checkstring (lua, 3);

  /* FIXME verify functon */

  for (ctx = lua_list.next; (ctx != &lua_list); ctx = ctx->next)
    if (ctx->l == lua)
      break;

  assert (ctx != &lua_list);

  u = plugin_robot_add (nick, description, pi_lua_robot_event_handler);

  if (!u) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  robot = malloc (sizeof (lua_robot_context_t));
  robot->robot = u;
  robot->handler = strdup (function);

  robot->next = ctx->robots.next;
  robot->next->prev = robot;
  robot->prev = &ctx->robots;
  robot->prev->next = robot;

  lua_pushboolean (lua, (u != NULL));
  return 1;
}

int pi_lua_delbot (lua_State * lua)
{
  lua_context_t *ctx;
  lua_robot_context_t *robot;
  unsigned char *nick = (unsigned char *) luaL_checkstring (lua, 1);
  plugin_user_t *u;

  for (ctx = lua_list.next; (ctx != &lua_list); ctx = ctx->next)
    if (ctx->l == lua)
      break;

  assert (ctx != &lua_list);

  u = plugin_user_find (nick);

  for (robot = ctx->robots.next; robot != &ctx->robots; robot = robot->next) {
    if (robot->robot == u)
      break;
  }

  if (robot == &ctx->robots) {
    lua_pushboolean (lua, 0);
    return 1;
  }

  plugin_robot_remove (robot->robot);

  robot->next->prev = robot->prev;
  robot->prev->next = robot->next;

  free (robot->handler);
  free (robot);

  lua_pushboolean (lua, 1);

  return 1;
}

void pi_lua_initbot (lua_context_t * ctx)
{
  ctx->robots.next = &ctx->robots;
  ctx->robots.prev = &ctx->robots;
}

void pi_lua_purgebots (lua_context_t * ctx)
{
  lua_robot_context_t *robot;

  for (robot = ctx->robots.next; robot != &ctx->robots; robot = ctx->robots.next) {
    plugin_robot_remove (robot->robot);

    robot->next->prev = robot->prev;
    robot->prev->next = robot->next;

    free (robot->handler);
    free (robot);
  }
}

/******************************************************************************************
 *  LUA Functions Custom Timer Handling
 */

typedef struct pi_lua_timer_context {
  struct pi_lua_timer_context *next, *prev;

  unsigned long interval;
  int funcref;
  int dataref;
  lua_State *lua;

  etimer_t timer;
} pi_lua_timer_context_t;

pi_lua_timer_context_t timerlist;

unsigned long pi_lua_handle_timeout (pi_lua_timer_context_t * ctx)
{
  lua_State *lua = ctx->lua;
  int retval = 0, result;

  lua_rawgeti (lua, LUA_REGISTRYINDEX, ctx->funcref);
  lua_rawgeti (lua, LUA_REGISTRYINDEX, ctx->dataref);
  result = lua_pcall (lua, 1, 1, 0);
  if (result) {
    unsigned char *error = (unsigned char *) luaL_checkstring (ctx->lua, 1);
    buffer_t *buf;

    DPRINTF ("LUA ERROR: %s\n", error);

    /* report error */
    buf = bf_alloc (32 + strlen (error));
    bf_printf (buf, _("LUA ERROR (Timer): %s\n"), error);
    plugin_report (buf);
    bf_free (buf);

    /* unlink */
    ctx->prev->next = ctx->next;
    ctx->next->prev = ctx->prev;

    /* delete timer */
    luaL_unref (lua, LUA_REGISTRYINDEX, ctx->funcref);
    luaL_unref (lua, LUA_REGISTRYINDEX, ctx->dataref);

    free (ctx);

    return 0;
  } else {
    /* retrieve return value */
    retval = lua_toboolean (lua, -1);
    lua_remove (lua, -1);
  }

  if (retval) {
    /* restart the timer */
    etimer_set (&ctx->timer, ctx->interval);
  } else {
    /* unlink */
    ctx->prev->next = ctx->next;
    ctx->next->prev = ctx->prev;

    /* destroy the timer */
    luaL_unref (lua, LUA_REGISTRYINDEX, ctx->funcref);
    luaL_unref (lua, LUA_REGISTRYINDEX, ctx->dataref);
    free (ctx);
  }

  return 0;
}

int pi_lua_timerclear (lua_State * lua)
{
  pi_lua_timer_context_t *ctx;

  for (ctx = timerlist.next; ctx != &timerlist; ctx = ctx->next) {
    if (ctx->lua != lua)
      continue;

    etimer_cancel (&ctx->timer);

    /* unlink */
    ctx->prev->next = ctx->next;
    ctx->next->prev = ctx->prev;

    /* destroy the timer */
    luaL_unref (lua, LUA_REGISTRYINDEX, ctx->funcref);
    luaL_unref (lua, LUA_REGISTRYINDEX, ctx->dataref);
    free (ctx);

    ctx = timerlist.next;
  }

  return 0;
}

int pi_lua_timeradd (lua_State * lua)
{
  unsigned long interval;
  pi_lua_timer_context_t *ctx;
  int n;

  n = lua_gettop (lua);
  if (n != 3) {
    lua_pushstring (lua, "incorrect argument count");
    lua_error (lua);		/* does not return */
  }

  interval = luaL_checknumber (lua, 1);
  luaL_argcheck (lua, lua_isfunction (lua, 2), 2, "function expected");
  /* no check for arg 3 since this can be anything the user wants. */

  ctx = malloc (sizeof (pi_lua_timer_context_t));
  if (!ctx) {
    lua_pushstring (lua, strerror (errno));
    lua_error (lua);
  }
  memset (ctx, 0, sizeof (pi_lua_timer_context_t));
  ctx->lua = lua;
  ctx->interval = interval;

  lua_pushvalue (lua, 2);
  ctx->funcref = luaL_ref (lua, LUA_REGISTRYINDEX);

  lua_pushvalue (lua, 3);
  ctx->dataref = luaL_ref (lua, LUA_REGISTRYINDEX);

  ctx->next = &timerlist;
  ctx->prev = timerlist.prev;
  ctx->next->prev = ctx;
  ctx->prev->next = ctx;

  etimer_init (&ctx->timer, (etimer_handler_t *) pi_lua_handle_timeout, ctx);
  etimer_set (&ctx->timer, interval);

  return 0;
}

/******************************************************************************************
 *  LUA Functions Custom Command Handling
 */

typedef struct pi_lua_command_context {
  struct pi_lua_command_context *next, *prev;

  unsigned char *name;
  lua_State *lua;
} pi_lua_command_context_t;

pi_lua_command_context_t pi_lua_command_list;

unsigned long handler_luacommand (plugin_user_t * user, buffer_t * output, void *priv,
				  unsigned int argc, unsigned char **argv)
{
  unsigned int i, result;
  pi_lua_command_context_t *ctx;

  /* find command */
  for (ctx = pi_lua_command_list.next; ctx != &pi_lua_command_list; ctx = ctx->next)
    if (!strcmp (ctx->name, argv[0]))
      break;

  /* registered command that was deleted? */
  ASSERT (ctx->name);

  lua_settop (ctx->lua, 0);

  /* specify function to call */
#if LUAVERSION == 51
  /* lua 5.1 */
  lua_getfield (ctx->lua, LUA_GLOBALSINDEX, ctx->name);
#endif

#if LUAVERSION == 50
  /* lua 5.0 */
  lua_pushstring (ctx->lua, ctx->name);
  lua_gettable (ctx->lua, LUA_GLOBALSINDEX);
#endif

  /* push nick argument */
  lua_pushstring (ctx->lua, user->nick);
  /* push command arguments as table */
  lua_newtable (ctx->lua);
  for (i = 0; i < argc; i++) {
    lua_pushnumber (ctx->lua, i);
    lua_pushstring (ctx->lua, argv[i]);
    lua_settable (ctx->lua, -3);
  }

  /* call funtion. */
  result = lua_pcall (ctx->lua, 2, 1, 0);
  if (result) {
    unsigned char *error = (unsigned char *) luaL_checkstring (ctx->lua, 1);
    buffer_t *buf;

    DPRINTF ("LUA ERROR: %s\n", error);

    buf = bf_alloc (32 + strlen (error) + strlen (ctx->name));

    bf_printf (buf, _("LUA ERROR ('%s'): %s\n"), ctx->name, error);

    plugin_report (buf);

    bf_free (buf);
  } else {
    /* retrieve return value */
    if (lua_isstring (ctx->lua, -1)) {
      unsigned char *retval = (unsigned char *) lua_tostring (ctx->lua, -1);

      bf_printf (output, "%s", retval);
    }
    lua_remove (ctx->lua, -1);
  }

  return 0;
}

/* lua reg command */
int pi_lua_cmdreg (lua_State * lua)
{
  pi_lua_command_context_t *ctx;
  unsigned long long caps = 0, ncaps = 0;
  unsigned char *cmd = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 2);
  unsigned char *desc = (unsigned char *) luaL_checkstring (lua, 3);

  lua_pushstring (lua, cmd);
  lua_gettable (lua, LUA_GLOBALSINDEX);
  if (lua_isnil (lua, -1)) {
    lua_remove (lua, -1);
    lua_pushstring (lua, __ ("No such LUA function."));
    return lua_error (lua);
  }
  lua_remove (lua, -1);

  parserights (rights, &caps, &ncaps);

  if (command_register (cmd, &handler_luacommand, caps, desc)) {
    lua_pushstring (lua, __ ("Command failed to register."));
    return lua_error (lua);
  }

  /* alloc and init */
  ctx = malloc (sizeof (pi_lua_command_context_t));
  if (!ctx) {
    command_unregister (cmd);
    lua_pushstring (lua, __ ("Could not allocate memory."));
    return lua_error (lua);
  }
  ctx->name = strdup (cmd);
  ctx->lua = lua;

  /* link in list */
  ctx->next = &pi_lua_command_list;
  ctx->prev = pi_lua_command_list.prev;
  ctx->next->prev = ctx;
  ctx->prev->next = ctx;

  lua_pushboolean (lua, 1);

  return 1;
}

/* lua del command */
int pi_lua_cmddel (lua_State * lua)
{
  pi_lua_command_context_t *ctx;
  unsigned char *cmd = (unsigned char *) luaL_checkstring (lua, 1);

  for (ctx = pi_lua_command_list.next; ctx != &pi_lua_command_list; ctx = ctx->next) {
    if ((lua != ctx->lua) || (strcmp (ctx->name, cmd)))
      continue;

    ctx->prev->next = ctx->next;
    ctx->next->prev = ctx->prev;

    command_unregister (cmd);

    free (ctx->name);
    free (ctx);

    break;
  }

  return 0;
}

int pi_lua_cmdsetrights (lua_State * lua)
{
  unsigned long long caps = 0, ncaps = 0;
  unsigned char *cmd = (unsigned char *) luaL_checkstring (lua, 1);
  unsigned char *rights = (unsigned char *) luaL_checkstring (lua, 2);

  parserights (rights, &caps, &ncaps);

  lua_pushboolean (lua, command_setrights (cmd, caps, ncaps));

  return 1;
}

/* clean out all command of this script */
int pi_lua_cmdclean (lua_State * lua)
{
  pi_lua_command_context_t *ctx;

  for (ctx = pi_lua_command_list.next; ctx != &pi_lua_command_list; ctx = ctx->next) {
    if (lua != ctx->lua)
      continue;

    ctx->prev->next = ctx->next;
    ctx->next->prev = ctx->prev;

    command_unregister (ctx->name);

    free (ctx->name);
    free (ctx);

    ctx = pi_lua_command_list.next;
  }

  return 0;
}

/******************************************************************************************
 *  LUA local functions
 */

int pi_lua_hubversion (lua_State * lua)
{
  lua_pushstring (lua, HUBSOFT_NAME);
  lua_pushstring (lua, AQUILA_VERSION);
  return 2;
}

/******************************************************************************************
 *  LUA Function registration
 */

typedef struct pi_lua_symboltable_element {
  const unsigned char *name;
  int (*func) (lua_State * lua);
} pi_lua_symboltable_element_t;

pi_lua_symboltable_element_t pi_lua_symboltable[] = {
  /* all user info related functions */
  {"GetUserIP", pi_lua_getuserip,},
  {"GetUserShare", pi_lua_getusershare,},
  {"GetUserShareNum", pi_lua_getusersharenum,},
  {"GetUserClient", pi_lua_getuserclient,},
  {"GetUserClientVersion", pi_lua_getuserclientversion,},
  {"GetUserSlots", pi_lua_getuserslots,},
  {"GetUserHubs", pi_lua_getuserhubs,},
  {"GetUserRights", pi_lua_getuserrights,},
  {"SetUserRights", pi_lua_setuserrights,},
  {"GetUserGroup", pi_lua_getusergroup,},
  {"GetUserSupports", pi_lua_getusersupports,},
  {"GetUserMyINFO", pi_lua_getusermyinfo,},

  {"UserIsOP", pi_lua_userisop,},
  {"UserIsOnline", pi_lua_userisonline,},
  {"UserIsActive", pi_lua_userisactive,},
  {"UserIsRegistered", pi_lua_userisregistered,},
  {"UserIsZombie", pi_lua_useriszombie,},

  /* kick and ban functions */
  {"UserKick", pi_lua_user_kick,},
  {"UserDrop", pi_lua_user_drop,},
  {"UserBan", pi_lua_user_ban,},
  {"UserBanNick", pi_lua_user_bannick,},
  {"UserBanIP", pi_lua_user_banip,},
  {"UserBanIPHard", pi_lua_user_banip_hard,},
  {"BanIP", pi_lua_banip,},
  {"BanIPHard", pi_lua_banip_hard,},
  {"UnBan", pi_lua_unban,},
  {"UnBanNick", pi_lua_unbannick,},
  {"UnBanIP", pi_lua_unbanip,},
  {"UnBanIPHard", pi_lua_unbanip_hard,},
  {"Zombie", pi_lua_user_zombie,},
  {"UnZombie", pi_lua_user_unzombie,},

  {"FindNickBan", pi_lua_findnickban,},
  {"FindIPBan", pi_lua_findipban,},

  {"Report", pi_lua_report,},

  /* hub message functions */
  {"ChatToAll", pi_lua_sendtoall,},
  {"ChatToNick", pi_lua_sendtonick,},
  {"ChatToRights", pi_lua_sendtorights,},
  {"PMToAll", pi_lua_sendpmtoall,},
  {"PMToNick", pi_lua_sendpmtonick,},
  {"PMToRights", pi_lua_sendpmtorights,},

  {"RawToNick", pi_lua_rawtonick,},
  {"RawToAll", pi_lua_rawtoall,},
  {"RawToRights", pi_lua_rawtorights,},

  /* account management */
  {"GroupCreate", pi_lua_group_create,},
  {"GroupInUse", pi_lua_group_inuse,},
  {"GroupRights", pi_lua_group_setrights,},
  {"GroupDelete", pi_lua_group_inuse,},
  {"GroupFind", pi_lua_group_find,},
  {"AccountCreate", pi_lua_account_create,},
  {"AccountDelete", pi_lua_account_delete,},
  {"AccountPasswd", pi_lua_account_passwd,},
  {"AccountPwGen", pi_lua_account_pwgen,},
  {"AccountFind", pi_lua_account_find,},
  {"AccountList", pi_lua_account_list,},
  {"AccountRights", pi_lua_account_setrights,},
  {"AccountLastLogin", pi_lua_account_lastlogin,},

  /* hubinfo stat related info */
  {"GetActualUsersTotal", pi_lua_getuserstotal,},

  /* robot functions */
  {"AddBot", pi_lua_addbot,},
  {"DelBot", pi_lua_delbot,},

  /* lua created command functions */
  {"RegCommand", pi_lua_cmdreg,},
  {"DelCommand", pi_lua_cmddel,},
  {"SetCommandRights", pi_lua_cmdsetrights,},

  /* config functions */
  {"SetConfig", pi_lua_setconfig,},
  {"GetConfig", pi_lua_getconfig,},

  /* timer functions */
  {"Timer", pi_lua_timeradd,},

  /* returns hub version */
  {"getHubVersion", pi_lua_hubversion,},

  {NULL, NULL}
};

int pi_lua_register_functions (lua_State * l)
{
  pi_lua_symboltable_element_t *cmd;

  for (cmd = pi_lua_symboltable; cmd->name; cmd++)
    lua_register (l, cmd->name, cmd->func);

  return 1;
}

/***************************************************************************************/

#if LUAVERSION == 50
/* This is only necessary for LUA 5.0.x */

/*
 * Lua libraries that we are going to load.
 */
static const luaL_reg lualibs[] = {
  {"base", luaopen_base},
  {"table", luaopen_table},
  {"io", luaopen_io},
  {"string", luaopen_string},
  {"math", luaopen_math},
  {"debug", luaopen_debug},
  {"loadlib", luaopen_loadlib},
  {NULL, NULL}
};

/*
 * Loads the above mentioned libraries.
 */
static void openlualibs (lua_State * l)
{
  const luaL_reg *lib;

  for (lib = lualibs; lib->func != NULL; lib++) {
    lib->func (l);		/* Open the library */
    /* 
     * Flush the stack, by setting the top to 0, in order to
     * ignore any result given by the library load function.
     */
    lua_settop (l, 0);
  }
}
#endif

/******************************************************************************************
 *  LUA script handling utilities
 */

unsigned int pi_lua_load (buffer_t * output, unsigned char *name)
{
  int result, i;
  lua_State *l;
  lua_context_t *ctx;

  /* first we check if a script like this has already been loaded.. */
  for (ctx = lua_list.next; ctx != &lua_list; ctx = ctx->next) {
    if (!strcmp (name, ctx->name))
      break;
  };

  if (ctx != &lua_list)
    pi_lua_close (name);

  /* load script */
#if LUAVERSION == 50
  l = lua_open ();
  openlualibs (l);		/* Load Lua libraries */
#elif LUAVERSION == 51
  l = luaL_newstate ();
  luaL_openlibs (l);
#endif
  pi_lua_register_functions (l);	/* register lua commands */

  /* load the file */
  result = luaL_loadfile (l, name);
  if (result) {
    unsigned char *error = (unsigned char *) luaL_checkstring (l, 1);

    bf_printf (output, _("LUA ERROR: %s\n"), error);

    goto error;
  }

  /* alloc and init context */
  ctx = malloc (sizeof (lua_context_t));
  ctx->l = l;
  ctx->name = strdup (name);
  ctx->eventmap = 0;

  /* add into list */
  ctx->next = &lua_list;
  ctx->prev = lua_list.prev;
  ctx->prev->next = ctx;
  ctx->next->prev = ctx;
  pi_lua_initbot (ctx);

  lua_ctx_cnt++;
  if (lua_ctx_peak > lua_ctx_cnt)
    lua_ctx_peak = lua_ctx_cnt;

  result = lua_pcall (l, 0, LUA_MULTRET, 0);
  if (result) {
    unsigned char *error = (unsigned char *) luaL_checkstring (l, 1);

    bf_printf (output, _("LUA ERROR: %s\n"), error);

    goto late_error;
  }

  /* determine eventhandlers */
  for (i = 0; pi_lua_eventnames[i] != NULL; i++) {
    lua_pushstring (ctx->l, pi_lua_eventnames[i]);
    lua_gettable (ctx->l, LUA_GLOBALSINDEX);
    if (!lua_isnil (ctx->l, -1)) {
      ctx->eventmap |= (1 << i);
      /* if not register yet, now register the event handler for this event */
      if (!(pi_lua_eventmap & (1 << i))) {
	plugin_request (plugin_lua, i, (plugin_event_handler_t *) & pi_lua_event_handler);
	pi_lua_eventmap |= (1 << i);
      }
    }
    lua_remove (ctx->l, -1);
  }

  /* add global variables */
  /* hub version */
  lua_pushstring (ctx->l, "AquilaVersion");
  lua_pushstring (ctx->l, AQUILA_VERSION);
  lua_settable (ctx->l, LUA_GLOBALSINDEX);

  /* reset stack */
  lua_settop (l, 0);

  return 1;

late_error:
  ctx->next->prev = ctx->prev;
  ctx->prev->next = ctx->next;
  pi_lua_purgebots (ctx);
  pi_lua_cmdclean (l);
  pi_lua_timerclear (l);
  free (ctx->name);
  free (ctx);
  lua_ctx_cnt--;

error:
  lua_close (l);
  return 0;
}

unsigned int pi_lua_close (unsigned char *name)
{
  unsigned long i;
  unsigned long long eventmap;
  lua_context_t *ctx, *ctx2;

  for (ctx = lua_list.next; ctx != &lua_list; ctx = ctx->next) {
    if (strcmp (name, ctx->name))
      continue;

    pi_lua_timerclear (ctx->l);
    pi_lua_cmdclean (ctx->l);
    pi_lua_purgebots (ctx);

    lua_close (ctx->l);
    free (ctx->name);

    ctx->next->prev = ctx->prev;
    ctx->prev->next = ctx->next;

    /* get a list of all events in use */
    eventmap = 0LL;
    for (ctx2 = lua_list.next; ctx2 != &lua_list; ctx2 = ctx2->next) {
      eventmap |= ctx2->eventmap;
    }

    /* determine events only used by this script */
    ASSERT ((pi_lua_eventmap & ~eventmap) == (ctx->eventmap & ~eventmap));
    eventmap = ctx->eventmap & ~eventmap;

    /* free those events */
    for (i = 0; pi_lua_eventnames[i] != NULL; i++) {
      if (eventmap & (1 << i)) {
	pi_lua_eventmap &= ~(1 << i);
	plugin_ignore (plugin_lua, i, (plugin_event_handler_t *) & pi_lua_event_handler);
      }
    }

    /* free the context */
    free (ctx);
    lua_ctx_cnt--;

    return 1;
  }

  return 0;
}

/******************************************************************************************
 *  LUA command handlers
 */

unsigned long handler_luastat (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  lua_context_t *ctx;

  bf_printf (output, _("Lua stats\nVersion: %s\nScripts count/peak: %d/%d"), LUA_VERSION,
	     lua_ctx_cnt, lua_ctx_peak);

  if (!lua_ctx_cnt) {
    bf_printf (output, _("\nNo LUA scripts running.\n"));
    return 1;
  }

  bf_printf (output, _("\nRunning LUA scripts:\n"));

  for (ctx = lua_list.next; ctx != &lua_list; ctx = ctx->next) {
    bf_printf (output, " %s (%s)\n", ctx->name, format_size (lua_getgccount (ctx->l) * 1024));
  }

  return 1;
}

unsigned long handler_luaload (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  if (argc != 2) {
    bf_printf (output, _("Usage: %s <script>"), argv[0]);
    return 0;
  }

  if (pi_lua_load (output, argv[1])) {
    bf_printf (output, _("Lua script '%s' loaded.\n"), argv[1]);
  } else {
    bf_printf (output, _("Lua script '%s' failed to load.\n"), argv[1]);
  }

  return 0;
}

unsigned long handler_luaclose (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{

  if (argc != 2) {
    bf_printf (output, _("Usage: %s <script>"), argv[0]);
    return 0;
  }

  if (pi_lua_close (argv[1])) {
    bf_printf (output, _("Lua script '%s' unloaded.\n"), argv[1]);
  } else {
    bf_printf (output, _("Lua script '%s' not found.\n"), argv[1]);
  }

  return 0;
}


/******************************************************************************************
 * lua function - event 
 */

unsigned long pi_lua_event_handler (plugin_user_t * user, buffer_t * output,
				    unsigned long event, buffer_t * token)
{
  int result = PLUGIN_RETVAL_CONTINUE;
  lua_context_t *ctx;

  pi_lua_eventuser = user;
  for (ctx = lua_list.next; (ctx != &lua_list) && (!result); ctx = ctx->next) {
    /* script doesn't have event handler */
    if (!(ctx->eventmap & (1 << event)))
      continue;

    /* clear stack */
    lua_settop (ctx->l, 0);

    /* specify function to call */
    /* lua 5.1 
       lua_getfield (ctx->l, LUA_GLOBALSINDEX, command);
     */

    /* lua 5.0 */
    lua_pushstring (ctx->l, pi_lua_eventnames[event]);
    lua_gettable (ctx->l, LUA_GLOBALSINDEX);

    /* push arguments */
    lua_pushstring (ctx->l, (user ? user->nick : (unsigned char *) ""));
    if (event == PLUGIN_EVENT_CONFIG) {
      config_element_t *elem = (config_element_t *) token;

      lua_pushstring (ctx->l, (elem ? elem->name : (unsigned char *) ""));
    } else {
      lua_pushstring (ctx->l, (token ? token->s : (unsigned char *) ""));
    }

    /* call funtion. */
    result = lua_pcall (ctx->l, 2, 1, 0);
    if (result) {
      unsigned char *error = (unsigned char *) luaL_checkstring (ctx->l, 1);
      buffer_t *buf;

      DPRINTF ("LUA ERROR: %s\n", error);

      buf = bf_alloc (32 + strlen (error) + strlen (ctx->name));

      bf_printf (buf, _("LUA ERROR ('%s'): %s\n"), ctx->name, error);

      plugin_report (buf);

      bf_free (buf);

      /* do not drop message if handler failed */
      result = PLUGIN_RETVAL_CONTINUE;
    }

    /* retrieve return value */
    if (lua_isboolean (ctx->l, -1)) {
      result = lua_toboolean (ctx->l, -1);
      lua_remove (ctx->l, -1);
    }
  }
  pi_lua_eventuser = NULL;

  return result;
}


unsigned long pi_lua_event_save (plugin_user_t * user, void *dummy, unsigned long event, void *arg)
{
  xml_node_t *node = arg;
  lua_context_t *ctx;

  node = xml_node_add (node, "Lua");
  for (ctx = lua_list.next; (ctx != &lua_list); ctx = ctx->next)
    xml_node_add_value (node, "LuaScript", XML_TYPE_STRING, ctx->name);

  return PLUGIN_RETVAL_CONTINUE;
}

unsigned long pi_lua_event_load_old (plugin_user_t * user, void *dummy, unsigned long event,
				     buffer_t * token);
unsigned long pi_lua_event_load (plugin_user_t * user, void *dummy, unsigned long event, void *arg)
{
  xml_node_t *node = arg;
  lua_context_t *ctx;
  buffer_t *buf;

  if (!arg)
    return pi_lua_event_load_old (user, dummy, event, NULL);

  /* unload all scripts */
  ctx = lua_list.next;
  while (ctx != &lua_list) {
    pi_lua_close (ctx->name);
    ctx = lua_list.next;
  }

  buf = bf_alloc (10240);

  node = xml_node_find (node, "Lua");
  for (node = node->children; node; node = xml_next (node)) {
    pi_lua_load (buf, node->value);
    if (bf_used (buf)) {
      plugin_report (buf);
      bf_clear (buf);
    }
  }
  bf_free (buf);

  return PLUGIN_RETVAL_CONTINUE;
}

unsigned long pi_lua_event_load_old (plugin_user_t * user, void *dummy,
				     unsigned long event, buffer_t * token)
{
  unsigned int i;
  FILE *fp;
  unsigned char buffer[10240];
  lua_context_t *ctx;
  buffer_t *buf;

  /* unload all scripts */
  ctx = lua_list.next;
  while (ctx != &lua_list) {
    pi_lua_close (ctx->name);
    ctx = lua_list.next;
  }

  /* load scripts */
  fp = fopen (pi_lua_savefile, "r+");
  if (!fp) {
    plugin_perror ("LUA: ERROR loading %s", pi_lua_savefile);
    return PLUGIN_RETVAL_CONTINUE;
  }

  buf = bf_alloc (10240);
  fgets (buffer, sizeof (buffer), fp);
  while (!feof (fp)) {
    for (i = 0; buffer[i] && buffer[i] != '\n' && (i < sizeof (buffer)); i++);
    if (i == sizeof (buffer))
      break;
    if (buffer[i] == '\n')
      buffer[i] = '\0';

    pi_lua_load (buf, buffer);
    if (bf_used (buf)) {
      plugin_report (buf);
      bf_clear (buf);
    }
    fgets (buffer, sizeof (buffer), fp);
  }
  bf_free (buf);
  fclose (fp);

  return PLUGIN_RETVAL_CONTINUE;
}


/******************************* INIT *******************************************/

int pi_lua_init ()
{
  pi_lua_savefile = strdup ("lua.conf");
  pi_lua_eventmap = 0;
  pi_lua_eventuser = NULL;

  lua_list.next = &lua_list;
  lua_list.prev = &lua_list;
  lua_list.l = NULL;
  lua_list.name = NULL;
  lua_ctx_cnt = 0;
  lua_ctx_peak = 0;

  timerlist.next = &timerlist;
  timerlist.prev = &timerlist;

  pi_lua_command_list.next = &pi_lua_command_list;
  pi_lua_command_list.prev = &pi_lua_command_list;
  pi_lua_command_list.name = NULL;
  pi_lua_command_list.lua = NULL;

  plugin_lua = plugin_register ("lua");

  plugin_request (plugin_lua, PLUGIN_EVENT_LOAD, (plugin_event_handler_t *) & pi_lua_event_load);
  plugin_request (plugin_lua, PLUGIN_EVENT_SAVE, (plugin_event_handler_t *) & pi_lua_event_save);

  command_register ("luastat", &handler_luastat, CAP_CONFIG, _("Show lua stats."));
  command_register ("luaload", &handler_luaload, CAP_CONFIG, _("Load a lua script."));
  command_register ("luaremove", &handler_luaclose, CAP_CONFIG, _("Remove a lua script."));

  pi_lua_event_load (NULL, NULL, 0, NULL);

  return 0;
}
