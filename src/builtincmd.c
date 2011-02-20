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

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <limits.h>

#ifdef ENABLE_NLS
#include <locale.h>
#endif

#include "../config.h"
#ifndef __USE_W32_SOCKETS
#  include <sys/socket.h>
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#  include <arpa/inet.h>
#else
#  include <winsock2.h>
#endif /* __USE_W32_SOCKETS */

#include <sys/time.h>

#include "aqtime.h"
#include "defaults.h"
#include "builtincmd.h"
#include "plugin.h"
#include "commands.h"
#include "utils.h"

#ifdef USE_WINDOWS
#  include "sys_windows.h"
#endif

#ifdef GEOIP
#include <GeoIP.h>
GeoIP *gi;
#endif

unsigned int MinPwdLength;
unsigned long AutoSaveInterval;
unsigned char *ReportTarget;
unsigned long KickMaxBanTime;
unsigned int KickNoBanMayBan;

struct timeval savetime;

extern unsigned int pi_iplog_find (unsigned char *nick, uint32_t * ip);

#ifndef HAVE_STRCASESTR

#include <ctype.h>

char *strcasestr (char *haystack, char *needle)
{
  if (!*needle)
    return NULL;

  for (; *haystack; haystack++) {
    if (tolower (*haystack) == tolower (*needle)) {
      char *h, *n;

      for (h = haystack, n = needle; *h && *n; h++, n++) {
	if (tolower (*h) != tolower (*n))
	  break;
      }
      if (!*n)
	return haystack;
    }
  }
  return NULL;
}
#endif

/* say command */
unsigned long handler_say (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			   unsigned char **argv)
{
  unsigned int i;
  buffer_t *buf;

  /* build message */
  buf = bf_alloc (10240);
  *buf->e = '\0';
  for (i = 1; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);
  if (*buf->s == ' ')
    buf->s++;

  /* make hubsec say it */
  plugin_user_say (NULL, buf);

  bf_free (buf);
  return 0;
}

unsigned long handler_warn (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			    unsigned char **argv)
{
  unsigned int i;
  buffer_t *buf;
  plugin_user_t *tgt;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick> <warning>"), argv[0]);
    return 0;
  }

  /* find target */
  tgt = plugin_user_find (argv[1]);
  if (!tgt) {
    bf_printf (output, _("User %s not found."), argv[1]);
    return 0;
  }

  /* build message */
  buf = bf_alloc (10240);
  *buf->e = '\0';
  bf_printf (buf, _("%s is WARNING you: "), user->nick);
  for (i = 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);
  if (*buf->s == ' ')
    buf->s++;

  /* make hubsec say it */
  plugin_user_sayto (NULL, tgt, buf, 0);

  bf_free (buf);

  return 0;
}

/* say command */
unsigned long handler_shutdown (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  buffer_t *buf;
  plugin_user_t *tgt = NULL, *prev = NULL;

  buf = bf_alloc (10240);
  *buf->e = '\0';

  if (argc > 1) {
    /* build message */
    for (i = 1; i < argc; i++)
      bf_printf (buf, " %s", argv[i]);
    if (*buf->s == ' ')
      buf->s++;
  } else {
    bf_printf (buf, _("Hub shutdown in progress."));
  }

  /* send to all users */
  while (plugin_user_next (&tgt)) {
    prev = tgt;
    if (plugin_user_sayto (user, tgt, buf, 1) < 0)
      tgt = prev;
  }

  bf_free (buf);

  exit (0);

  return 0;
}

/* say command */
unsigned long handler_version (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  bf_printf (output, _("This is %s Version %s"), HUBSOFT_NAME, AQUILA_VERSION);
  return 0;
}

unsigned long handler_massall (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  buffer_t *buf;
  plugin_user_t *tgt = NULL, *prev = NULL;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <message>"), argv[0]);
    return 0;
  }

  /* build message */
  buf = bf_alloc (10240);
  *buf->e = '\0';
  for (i = 1; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);
  if (*buf->s == ' ')
    buf->s++;

  /* send to all users */
  i = 0;
  while (plugin_user_next (&tgt)) {
    prev = tgt;
    if (plugin_user_priv (NULL, tgt, user, buf, 1) < 0) {
      tgt = prev;
    } else {
      i++;
    }
  }
  bf_free (buf);

  /* return result */
  bf_printf (output, _("Message sent to %lu users."), i);

  return 0;
}

unsigned long handler_report (plugin_user_t * user, buffer_t * output, void *priv,
			      unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  buffer_t *buf;
  plugin_user_t *tgt = NULL;
  config_element_t *reporttarget;
  struct in_addr source, target;
  char sa[16], da[16];

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick> <reason>"), argv[0]);
    return 0;
  }

  /* find config value */
  reporttarget = config_find ("ReportTarget");
  if (!reporttarget) {
    bf_printf (output, _("Report could not be sent. Reporting is disabled."));
    return 0;
  }

  tgt = plugin_user_find (argv[1]);
  if (tgt) {
    target.s_addr = tgt->ipaddress;
  } else {
    target.s_addr = 0;
  }
  source.s_addr = user->ipaddress;

  /* build message */
  buf = bf_alloc (10240);
  *buf->e = '\0';

  snprintf (sa, 15, "%s", inet_ntoa (source));
  if (target.s_addr) {
    snprintf (da, 15, "%s", inet_ntoa (target));
    bf_printf (buf, _("User %s (%s) reports %s (%s): "), user->nick, sa, argv[1], da);
  } else
    bf_printf (buf, _("User %s (%s) reports %s (not logged in): "), user->nick, sa, argv[1]);

  for (i = 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);
  if (*buf->s == ' ')
    buf->s++;


  /* extract user */
  tgt = plugin_user_find (*reporttarget->val.v_string);
  if (!tgt) {
    if (**reporttarget->val.v_string) {
      bf_printf (output, _("Report could not be sent, %s not found."), *reporttarget->val.v_string);
    } else {
      bf_printf (output, _("Report could not be sent, target not found."));
    }
    return 0;
  }

  /* send message */
  plugin_user_priv (NULL, tgt, NULL, buf, 0);

  /* return result */
  bf_printf (output, _("Report sent."));

  return 0;
}

unsigned long handler_myip (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			    unsigned char **argv)
{
  struct in_addr ip;

  ip.s_addr = user->ipaddress;

  bf_printf (output, _("Your IP is %s\n"), inet_ntoa (ip));

  return 0;
}


unsigned long handler_kick (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			    unsigned char **argv)
{
  unsigned int i = 0;
  buffer_t *buf;
  plugin_user_t *target;
  struct in_addr ip;
  unsigned char *c;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick> <reason>"), argv[0]);
    return 0;
  };

  /* rebuild reason */
  buf = bf_alloc (1024);
  *buf->e = '\0';
  for (i = 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);

  /* find target */
  target = plugin_user_find (argv[1]);
  if (!target) {
    bf_printf (output, _("User %s not found."), argv[1]);
    goto leave;
  }

  /* kick the user */
  ip.s_addr = target->ipaddress;
  bf_printf (output, _("Kicked user %s ( ip %s ) because: %.*s"), target->nick, inet_ntoa (ip),
	     bf_used (buf), buf->s);

  /* permban the user if the kick string contains _BAN_. */
  if ((c = strcasestr (buf->s, "_BAN_"))) {
    unsigned long total = 0;

    if (KickNoBanMayBan || (user->rights & CAP_BAN)) {
      total = time_parse (c + 5);
      if ((KickMaxBanTime == 0)
	  || ((KickMaxBanTime > 0) && (total <= KickMaxBanTime) && (total > 0))
	  || (user->rights & CAP_BAN)) {
	if (total != 0) {
	  bf_printf (output, _("\nBanning user for %s\n"), time_print (total));
	} else {
	  bf_printf (output, _("\nBanning user forever"));
	}
	plugin_user_ban (user, target, buf, total);
	goto leave;
      } else {
	bf_printf (output, _("\nSorry. You cannot ban users for longer than %s with a kick."),
		   time_print (KickMaxBanTime));
      }
    } else {
      bf_printf (output, _("\nSorry, you cannot ban."));
    }
  }

  /* actually kick the user. */
  plugin_user_kick (user, target, buf);

leave:
  bf_free (buf);

  return 0;
}

unsigned long handler_drop (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			    unsigned char **argv)
{
  unsigned int i = 0;
  buffer_t *buf;
  plugin_user_t *target;
  struct in_addr ip;
  unsigned char *c;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick> <reason>"), argv[0]);
    return 0;
  };

  /* rebuild reason */
  buf = bf_alloc (1024);
  *buf->e = '\0';
  bf_printf (buf, _("You were dropped by %s because: "), user->nick);
  for (i = 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);

  /* find target */
  target = plugin_user_find (argv[1]);
  if (!target) {
    bf_printf (output, _("User %s not found."), argv[1]);
    goto leave;
  }

  /* kick the user */
  ip.s_addr = target->ipaddress;
  bf_printf (output, _("Dropped user %s (ip %s) because: %.*s"), target->nick, inet_ntoa (ip),
	     bf_used (buf), buf->s);

  /* permban the user if the kick string contains _BAN_. */
  if ((c = strcasestr (buf->s, "_BAN_"))) {
    unsigned long total = 0;

    if (KickNoBanMayBan || (user->rights & CAP_BAN)) {
      total = time_parse (c + 5);
      if ((KickMaxBanTime == 0) || ((KickMaxBanTime > 0) && (total <= KickMaxBanTime))
	  || (user->rights & CAP_BAN)) {
	if (total != 0) {
	  bf_printf (output, _("\nBanning user for %s\n"), time_print (total));
	} else {
	  bf_printf (output, _("\nBanning user forever"));
	}
	plugin_user_ban (user, target, buf, total);
      } else {
	bf_printf (output, _("\nSorry. You cannot ban users for longer than %s with a drop."),
		   time_print (KickMaxBanTime));
      }
    } else {
      bf_printf (output, _("\nSorry, you cannot ban."));
    }
  }

  /* actually kick the user. */
  plugin_user_drop (target, buf);

leave:
  bf_free (buf);

  return 0;
}


unsigned long handler_zombie (plugin_user_t * user, buffer_t * output, void *priv,
			      unsigned int argc, unsigned char **argv)
{
  plugin_user_t *zombie;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick>"), argv[0]);
    return 0;
  }

  zombie = plugin_user_find (argv[1]);
  if (!zombie) {
    bf_printf (output, _("User %s not found."), argv[1]);
    return 0;
  }

  plugin_user_zombie (zombie);

  bf_printf (output, _("User %s's putrid flesh stinks up the place..."), argv[1]);

  return 0;
}

unsigned long handler_zombielist (plugin_user_t * user, buffer_t * output, void *priv,
				  unsigned int argc, unsigned char **argv)
{
  plugin_user_t *zombie = NULL;
  unsigned long count = 0;

  /* send to all users */
  bf_printf (output, _("The hub is infested by the following zombie horde:\n"));
  while (plugin_user_next (&zombie)) {
    if (!(zombie->flags & PLUGIN_FLAG_ZOMBIE))
      continue;
    if ((zombie == user) && (!(zombie->rights & CAP_OWNER)))
      continue;

    bf_printf (output, "%s\n", zombie->nick);
    count++;
  }
  if (!count)
    bf_printf (output, _("No zombies found!\n"));

  return 0;
}

unsigned long handler_unzombie (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{
  plugin_user_t *zombie;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick>"), argv[0]);
    return 0;
  }

  zombie = plugin_user_find (argv[1]);
  if (!zombie) {
    bf_printf (output, _("User %s not found."), argv[1]);
    return 0;
  }

  plugin_user_unzombie (zombie);

  bf_printf (output, _("User %s's putrid flesh is miraculously restored..."), argv[1]);

  return 0;
}

unsigned long handler_whoip (plugin_user_t * user, buffer_t * output, void *priv,
			     unsigned int argc, unsigned char **argv)
{
  struct in_addr ip, netmask, tmp;
  plugin_user_t *tgt;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <ip>"), argv[0]);
    return 0;
  };

  if (parse_ip (argv[1], &ip, &netmask)) {
    if (netmask.s_addr == 0xFFFFFFFF) {
      /* looking for single IP */
      if ((tgt = plugin_user_find_ip (NULL, ip.s_addr))) {
	do {
	  bf_printf (output, _("User %s is using IP %s\n"), tgt->nick, inet_ntoa (ip));
	  tgt = plugin_user_find_ip (tgt, ip.s_addr);
	} while (tgt);
      } else
	bf_printf (output, _("No one using IP %s found."), inet_ntoa (ip));
    } else {
      if ((tgt = plugin_user_find_net (NULL, ip.s_addr, netmask.s_addr))) {
	do {
	  tmp.s_addr = tgt->ipaddress;
	  bf_printf (output, _("User %s is using IP %s\n"), tgt->nick, inet_ntoa (tmp));
	  tgt = plugin_user_find_net (tgt, ip.s_addr, netmask.s_addr);
	} while (tgt);
      } else
	bf_printf (output, _("No one using IP %s found."), print_ip (ip, netmask));
    }
  } else {
    bf_printf (output, _("Sorry, \"%s\" is not a recognisable IP address."), argv[1]);
  }

  return 0;
}

unsigned long handler_unban (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			     unsigned char **argv)
{
  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick>"), argv[0]);
    return 0;
  }

  if (plugin_unban (argv[1])) {
    bf_printf (output, _("Nick %s unbanned."), argv[1]);
  } else {
    bf_printf (output, _("No ban for nick %s found."), argv[1]);
  }

  return 0;
}

unsigned long handler_unbanip (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  struct in_addr ip, netmask;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <ip>"), argv[0]);
    return 0;
  };

  if (parse_ip (argv[1], &ip, &netmask)) {
    if (plugin_unban_ip (ip.s_addr, netmask.s_addr)) {
      bf_printf (output, _("IP %s unbanned."), print_ip (ip, netmask));
    } else {
      bf_printf (output, _("No ban for IP %s found."), print_ip (ip, netmask));
    }
  } else {
    bf_printf (output, _("Sorry, \"%s\" is not a recognisable IP address."), argv[1]);
  }

  return 0;
}

unsigned long handler_unbanip_hard (plugin_user_t * user, buffer_t * output, void *priv,
				    unsigned int argc, unsigned char **argv)
{
  struct in_addr ip, netmask;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <ip>"), argv[0]);
    return 0;
  };

  if (parse_ip (argv[1], &ip, &netmask)) {
    if (plugin_unban_ip_hard (ip.s_addr, netmask.s_addr)) {
      bf_printf (output, _("IP %s unbanned."), print_ip (ip, netmask));
    } else {
      bf_printf (output, _("No ban for IP %s found."), print_ip (ip, netmask));
    }
  } else {
    bf_printf (output, _("Sorry, \"%s\" is not a recognisable IP address."), argv[1]);
  }

  return 0;
}

unsigned long handler_banip (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			     unsigned char **argv)
{
  unsigned int i = 0;
  unsigned long period = 0;
  buffer_t *buf;
  plugin_user_t *target;
  struct in_addr ip, netmask;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <ip/nick> [<period>] <reason>"), argv[0]);
    return 0;
  }

  buf = bf_alloc (1024);
  *buf->e = '\0';

  if (argv[2]) {
    period = time_parse (argv[2]);
  }

  for (i = period ? 3 : 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);

  target = plugin_user_find (argv[1]);
  if (target) {
    ip.s_addr = target->ipaddress;
    if (!period) {
      bf_printf (output, _("IP Banning user %s (ip %s) forever: %.*s"), target->nick,
		 inet_ntoa (ip), bf_used (buf), buf->s);
    } else {
      bf_printf (output, _("IP Banning user %s (ip %s) for %s: %.*s"), target->nick, inet_ntoa (ip),
		 time_print (period), bf_used (buf), buf->s);
    }
    plugin_user_banip (user, target, buf, period);
#ifdef PLUGIN_IPLOG
  } else if (pi_iplog_find (argv[1], (uint32_t *) & ip.s_addr)) {
    netmask.s_addr = 0xFFFFFFFF;
    bf_printf (output, _("User %s offline, found in iplog\n"), argv[1]);
    plugin_ban_ip (user, ip.s_addr, 0xFFFFFFFF, buf, period);
    if (!period) {
      bf_printf (output, _("IP Banning %s (ip %s) forever: %.*s."), argv[1], print_ip (ip, netmask),
		 bf_used (buf), buf->s);
    } else {
      bf_printf (output, _("IP Banning %s (ip %s) for %s: %.*s"), argv[1], print_ip (ip, netmask),
		 time_print (period), bf_used (buf), buf->s);
    }
#endif
  } else {
    if (parse_ip (argv[1], &ip, &netmask)) {
      plugin_ban_ip (user, ip.s_addr, netmask.s_addr, buf, period);
      if (!period) {
	bf_printf (output, _("IP Banning %s forever: %.*s."), print_ip (ip, netmask), bf_used (buf),
		   buf->s);
      } else {
	bf_printf (output, _("IP Banning %s for %s: %.*s"), print_ip (ip, netmask),
		   time_print (period), bf_used (buf), buf->s);
      }
    } else {
      bf_printf (output, _("User not found or IP address not valid: %s\n"), argv[1]);
    }
  }

  bf_free (buf);

  return 0;
}

unsigned long handler_bannick (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  unsigned int i = 0;
  unsigned long period = 0;
  buffer_t *buf;
  plugin_user_t *target;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick> [<period>] <reason>"), argv[0]);
    return 0;
  }

  /* read period */
  if (argv[2]) {
    period = time_parse (argv[2]);
  }
  /* build reason */
  buf = bf_alloc (1024);
  *buf->e = '\0';
  for (i = period ? 3 : 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);

  /* find target */
  target = plugin_user_find (argv[1]);
  if (!target) {
    bf_printf (output, _("User %s not found."), argv[1]);
  }

  /* ban him. */
  if (!period) {
    bf_printf (output, _("Banned nick %s forever: %.*s"), argv[1], bf_used (buf), buf->s);
  } else {
    bf_printf (output, _("Banned nick %s for %s: %.*s"), argv[1], time_print (period),
	       bf_used (buf), buf->s);
  }

  if (target) {
    plugin_user_bannick (user, target, buf, period);
  } else {
    plugin_ban_nick (user, argv[1], buf, period);
  }

  bf_free (buf);

  return 0;
}


unsigned long handler_ban (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			   unsigned char **argv)
{
  unsigned int i = 0;
  unsigned long period = 0;
  buffer_t *buf;
  plugin_user_t *target;
  struct in_addr ip;
  unsigned char *nick;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick> [<period>] <reason>"), argv[0]);
    return 0;
  }

  if (argv[2])
    period = time_parse (argv[2]);

  buf = bf_alloc (1024);
  *buf->e = '\0';
  for (i = period ? 3 : 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);


  target = plugin_user_find (argv[1]);
#ifdef PLUGIN_IPLOG
  if (!target) {
    if (!pi_iplog_find (argv[1], (uint32_t *) & ip.s_addr)) {
      bf_printf (output, _("User %s not found."), argv[1]);
      goto leave;
    }
    nick = argv[1];
    bf_printf (output, _("User %s not online, found in iplog.\n"), argv[1]);
    plugin_ban (user, nick, ip.s_addr, 0xFFFFFFFF, buf, period);
  } else {
    ip.s_addr = target->ipaddress;
    nick = target->nick;
    plugin_user_ban (user, target, buf, period);
  }
#else
  if (!target) {
    bf_printf (output, _("User %s not found."), argv[1]);
    goto leave;
  }
  ip.s_addr = target->ipaddress;
  nick = target->nick;
  plugin_user_ban (user, target, buf, period);
#endif

  if (!period) {
    bf_printf (output, _("Banning user %s (ip %s) forever: %.*s"), nick, inet_ntoa (ip),
	       bf_used (buf), buf->s);
  } else {
    bf_printf (output, _("Banning user %s (ip %s) for %s: %.*s"), nick, inet_ntoa (ip),
	       time_print (period), bf_used (buf), buf->s);
  }

leave:
  bf_free (buf);

  return 0;
}

unsigned long handler_banhard (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  unsigned int i = 0;
  unsigned long period = 0;
  buffer_t *buf;
  plugin_user_t *target;
  struct in_addr ip, netmask;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <ip/nick> [<period>] <reason>"), argv[0]);
    return 0;
  }

  if (argv[2])
    period = time_parse (argv[2]);

  buf = bf_alloc (1024);
  *buf->e = '\0';
  for (i = period ? 3 : 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);

  target = plugin_user_find (argv[1]);
  if (target) {
    ip.s_addr = target->ipaddress;
    if (!period) {
      bf_printf (output, _("HARD Banning user %s (ip %s) forever: %.*s"), target->nick,
		 inet_ntoa (ip), bf_used (buf), buf->s);
    } else {
      bf_printf (output, _("HARD Banning user %s (ip %s) for %s: %.*s"), target->nick,
		 inet_ntoa (ip), time_print (period), bf_used (buf), buf->s);
    }
    plugin_user_banip_hard (user, target, buf, period);
  } else {
    if (parse_ip (argv[1], &ip, &netmask)) {
      if (!period) {
	bf_printf (output, _("HARD Banning ip %s forever: %.*s"), print_ip (ip, netmask),
		   bf_used (buf), buf->s);
      } else {
	bf_printf (output, _("HARD Banning ip %s for %s: %.*s"), print_ip (ip, netmask),
		   time_print (period), bf_used (buf), buf->s);
      }
      plugin_ban_ip_hard (user, ip.s_addr, netmask.s_addr, buf, period);
    } else {
      bf_printf (output, _("User not found or ip address not valid: %s\n"), argv[1]);
    }
  }

  bf_free (buf);

  return 0;
}

unsigned long handler_banlist (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  struct in_addr ip;

  if (argc < 1) {
    bf_printf (output, _("Usage: %s [<ip|nick>]"), argv[0]);
    return 0;
  }

  if (argc < 2) {
    if (!plugin_banlist (output))
      bf_printf (output, _("No bans found."));
    goto leave;
  }
  if (inet_aton (argv[1], &ip)) {
    if (!plugin_user_findipban (output, ip.s_addr)) {
      bf_printf (output, _("No IP bans found for %s"), inet_ntoa (ip));
      goto leave;
    }
  } else {
    if (!plugin_user_findnickban (output, argv[1])) {
      bf_printf (output, _("No Nick bans found for %s"), argv[1]);
      goto leave;
    }
  }

leave:
  return 0;
}

unsigned long handler_hardbanlist (plugin_user_t * user, buffer_t * output, void *priv,
				   unsigned int argc, unsigned char **argv)
{
  struct in_addr ip;

  if (argc < 1) {
    bf_printf (output, _("Usage: %s [<ip|nick>]"), argv[0]);
    return 0;
  }

  if (argc < 2) {
    if (!plugin_hardbanlist (output))
      bf_printf (output, _("No bans found."));
    goto leave;
  }
  if (inet_aton (argv[1], &ip)) {
    if (!plugin_user_findiphardban (output, ip.s_addr)) {
      bf_printf (output, _("No IP bans found for %s"), inet_ntoa (ip));
      goto leave;
    }
  } else {
    bf_printf (output, _("Sorry, \"%s\" is not a recognisable IP address."), argv[1]);
  }

leave:
  return 0;
}

/* help command */
#include "hash.h"
extern command_t cmd_sorted;
extern command_t cmd_hashtable[COMMAND_HASHTABLE];

unsigned long handler_help (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			    unsigned char **argv)
{
  unsigned int j, hash;
  command_t *cmd, *list;

  if (argc < 2) {
    bf_printf (output, _("Available commands:\n"));
    for (cmd = cmd_sorted.onext; cmd != &cmd_sorted; cmd = cmd->onext)
      if (((user->rights & cmd->req_cap) == cmd->req_cap) || !cmd->req_cap
	  || (user->rights & CAP_OWNER))
	bf_printf (output, "%s: %s\n", cmd->name, cmd->help);

    bf_printf (output, _("Commands are preceded with ! or +\n"));
    bf_printf (output, _("\nThis hub is running %s Version %s. For more help, see %s\n"),
	       HUBSOFT_NAME, AQUILA_VERSION, HUBSOFT_HOMEPAGE);
    return 0;
  }

  for (j = 1; j < argc; j++) {
    hash = SuperFastHash (argv[j], strlen (argv[j]));
    list = &cmd_hashtable[hash & COMMAND_HASHMASK];
    for (cmd = list->next; cmd != list; cmd = cmd->next)
      if (!strcmp (cmd->name, argv[j]))
	break;

    if (!
	(((user->rights & cmd->req_cap) == cmd->req_cap) || !cmd->req_cap
	 || (user->rights & CAP_OWNER)))
      continue;

    if (cmd) {
      bf_printf (output, "%s: %s\n", cmd->name, cmd->help);
    } else {
      bf_printf (output, _("Command %s not found.\n"), argv[j]);
    }
  }

  return 0;
}

/* right handling */
unsigned long handler_rightcreate (plugin_user_t * user, buffer_t * output, void *priv,
				   unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  buffer_t *buf;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <name> <help>\n"), argv[0]);
    return 0;
  }

  buf = bf_alloc (1024);
  *buf->e = '\0';
  for (i = 2; i < argc; i++)
    bf_printf (buf, " %s", argv[i]);
  if (*buf->s == ' ')
    buf->s++;

  if (!cap_custom_add (argv[1], buf->s)) {
    bf_printf (output, _("Right %s could not be created.\n"), argv[1]);
  } else {
    bf_printf (output, _("Right %s created.\n"), argv[1]);
  }

  return 0;
}

unsigned long handler_rightdestroy (plugin_user_t * user, buffer_t * output, void *priv,
				    unsigned int argc, unsigned char **argv)
{
  if (argc < 3) {
    bf_printf (output, _("Usage: %s <name>\n"), argv[0]);
    return 0;
  }

  if (cap_custom_remove (argv[1]) < 0) {
    bf_printf (output, _("Right %s could not be found.\n"), argv[1]);
  } else {
    bf_printf (output, _("Right %s destroyed.\n"), argv[1]);
  }

  return 0;
}

/* user handling */
#include "user.h"
extern account_t *accounts;
extern account_type_t *accountTypes;

unsigned long handler_groupadd (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{
  unsigned long long cap = 0, ncap = 0;
  config_element_t *defaultrights;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <group> <rights>...\n"), argv[0]);
    flags_help (Capabilities, output);
    goto leave;
  }

  if (account_type_find (argv[1])) {
    bf_printf (output, _("Group %s already exists.\n"), argv[1]);
    goto leave;
  }

  if (argc > 2)
    flags_parse (Capabilities, output, argc, argv, 2, &cap, &ncap);

  if (!cap) {
    defaultrights = config_find ("user.defaultrights");
    cap = *defaultrights->val.v_cap;
  }

  /* verify if the user can actually assign these extra rights... */
  if (!(user->rights & CAP_OWNER)) {
    if (cap && (!(user->rights & CAP_INHERIT))) {
      bf_printf (output, _("You are not allowed to assign rights.\n"));
      goto leave;
    }
    if (cap & ~user->rights) {
      bf_printf (output, _("You are not allowed to assign the following rights to this group: "));
      flags_print ((Capabilities + CAP_PRINT_OFFSET), output, cap & ~user->rights);
      bf_strcat (output, "\n");
      goto leave;
    }
  }
  account_type_add (argv[1], cap);

  bf_printf (output, _("Group %s created with: "), argv[1]);
  flags_print ((Capabilities + CAP_PRINT_OFFSET), output, cap);
  bf_strcat (output, "\n");

leave:
  return 0;
}

unsigned long handler_groupcap (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{
  unsigned long long cap = 0, ncap = 0;
  account_type_t *type;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <group> <[+]right/-right>...\n"), argv[0]);
    flags_help (Capabilities, output);
    goto leave;
  }

  if (!(type = account_type_find (argv[1]))) {
    bf_printf (output, _("Group %s does not exist.\n"), argv[1]);
    goto leave;
  }

  if (argc > 2)
    flags_parse (Capabilities, output, argc, argv, 2, &cap, &ncap);

  /* verify if the user can actually assign these extra rights... */
  if (!(user->rights & CAP_OWNER)) {
    if (cap && (!(user->rights & CAP_INHERIT))) {
      bf_printf (output, _("You are not allowed to assign rights.\n"));
      goto leave;
    }
    if (cap & ~user->rights) {
      bf_printf (output, _("You are not allowed to assign the following rights to this group: "));
      flags_print ((Capabilities + CAP_PRINT_OFFSET), output, cap & ~user->rights);
      bf_strcat (output, "\n");
      goto leave;
    }

    if (ncap & ~user->rights) {
      bf_printf (output, _("You are not allowed to remove the following rights from this group: "));
      flags_print ((Capabilities + CAP_PRINT_OFFSET), output, ncap & ~user->rights);
      bf_strcat (output, "\n");
      goto leave;
    }
  }

  type->rights |= cap;
  type->rights &= ~ncap;

  bf_printf (output, _("Group %s modified. Current rights:"), argv[1]);
  flags_print ((Capabilities + CAP_PRINT_OFFSET), output, type->rights);
  bf_strcat (output, "\n");

leave:
  return 0;
}

unsigned long handler_groupdel (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{
  account_type_t *type;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <group>"), argv[0]);
    return 0;
  }



  if (!(type = account_type_find (argv[1]))) {
    bf_printf (output, _("Group %s does not exist.\n"), argv[1]);
    goto leave;
  }

  if (type->refcnt) {
    bf_printf (output, _("Group %s still has %ld users.\n"), argv[1], type->refcnt);
    goto leave;
  }

  account_type_del (type);
  bf_printf (output, _("Group %s deleted.\n"), argv[1]);

leave:
  return 0;
}

unsigned long handler_grouplist (plugin_user_t * user, buffer_t * output, void *priv,
				 unsigned int argc, unsigned char **argv)
{
  account_type_t *type;

  for (type = accountTypes; type; type = type->next) {
    bf_printf (output, "%s: ", type->name);
    flags_print ((Capabilities + CAP_PRINT_OFFSET), output, type->rights);
    bf_strcat (output, "\n");
  };

  return 0;
}

unsigned long handler_userlist (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{
  account_type_t *type;
  account_t *account;
  unsigned int i, cnt;

  if (argc == 1) {
    for (type = accountTypes; type; type = type->next) {
      bf_printf (output, "\nGroup %s:\n ", type->name);
      for (cnt = 0, account = accounts; account; account = account->next) {
	if (account->classp != type)
	  continue;
	bf_printf (output, " %s,", account->nick, account->classp->name);
	cnt++;
      };
      if (cnt) {
	output->e--;
	*output->e = '\0';
      } else
	bf_printf (output, " No users.");
    };
  } else {
    for (i = 1; i < argc; i++) {
      type = account_type_find (argv[i]);
      if (!type) {
	bf_printf (output, _("Group %s does not exist.\n"), argv[1]);
	continue;
      }
      bf_printf (output, _("\nGroup %s:\n "), type->name);
      for (cnt = 0, account = accounts; account; account = account->next) {
	if (account->class == type->id) {
	  bf_printf (output, " %s,", account->nick);
	  cnt++;
	}
      };
      /* remove trailing , */
      if (cnt) {
	output->e--;
	*output->e = '\0';
      }
    }
  }

  return 0;
}

unsigned long handler_useradd (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  unsigned long long cap = 0, ncap = 0;
  account_type_t *type;
  account_t *account;
  plugin_user_t *target;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <nick> <group> [<rights...>]"), argv[0]);
    return 0;
  }

  if (account_find (argv[1])) {
    bf_printf (output, _("User %s already exists.\n"), argv[1]);
    goto leave;
  }
  if (!(type = account_type_find (argv[2]))) {
    bf_printf (output, _("Group %s does not exist.\n"), argv[2]);
    goto leave;
  }

  if (argc > 3)
    flags_parse (Capabilities, output, argc, argv, 3, &cap, &ncap);

  if (!(user->rights & CAP_OWNER)) {
    /* verify the user can assign users to this group */
    if (type->rights & ~user->rights) {
      bf_printf (output, _("You are not allowed to assign a user to this group.\n"));
      goto leave;
    }

    /* verify if the user can actually assign these extra rights... */
    if (cap && (!(user->rights & CAP_INHERIT))) {
      bf_printf (output, _("You are not allowed to assign a user extra rights.\n"));
      goto leave;
    }
    if (cap & ~user->rights) {
      bf_printf (output, _("You are not allowed to assign this user: "));
      flags_print ((Capabilities + CAP_PRINT_OFFSET), output, cap & ~user->rights);
      bf_strcat (output, "\n");
      goto leave;
    }
  }

  account = account_add (type, user->nick, argv[1]);
  account->rights |= cap;

  bf_printf (output, _("User %s created with group %s.\nCurrent rights:"), account->nick,
	     type->name);
  flags_print ((Capabilities + CAP_PRINT_OFFSET), output, account->rights | type->rights);
  bf_strcat (output, "\n");

  /* if user is online, warm him of his reg and notify to op we did so. */
  target = plugin_user_find (argv[1]);
  if (target) {
    buffer_t *message;

    /* warn user */
    message = bf_alloc (1024);
    bf_printf (message,
	       _("You have been registered by %s. Please use !passwd <password> to set a password "
		 "and relogin to gain your new rights. You have been assigned:\n"), user->nick);
    flags_print ((Capabilities + CAP_PRINT_OFFSET), message, account->rights | type->rights);
    plugin_user_sayto (NULL, target, message, 0);
    bf_free (message);

    bf_printf (output,
	       _
	       ("User is already logged in. He has been told to set a password and to relogin.\n"));
  } else {
    bf_printf (output,
	       _
	       ("No user with nickname %s is currently logged in. Please notify the user yourself.\n"),
	       argv[1]);
  }
leave:
  return 0;
}

unsigned long handler_usercap (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  unsigned long long cap = 0, ncap = 0;
  account_t *account;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <nick> <[+]right/-right>...\n"), argv[0]);
    flags_help (Capabilities, output);
    goto leave;
  }

  if (!(user->rights & CAP_INHERIT)) {
    bf_printf (output, _("You are not allowed to assign a user extra rights.\n"));
    goto leave;
  }

  if (!(account = account_find (argv[1]))) {
    bf_printf (output, _("User %s not found."), argv[1]);
    goto leave;
  }

  if (argc > 2)
    flags_parse (Capabilities, output, argc, argv, 2, &cap, &ncap);

  /* verify if the user can actually assign these extra rights... */
  if (!(user->rights & CAP_OWNER)) {
    if (cap & ~user->rights) {
      bf_printf (output, _("You are not allowed to assign the following rights to this user: "));
      flags_print ((Capabilities + CAP_PRINT_OFFSET), output, cap & ~user->rights);
      bf_strcat (output, "\n");
      goto leave;
    }
    if (ncap & ~user->rights) {
      bf_printf (output, _("You are not allowed to touch: "));
      flags_print ((Capabilities + CAP_PRINT_OFFSET), output, ncap & ~user->rights);
      bf_strcat (output, "\n");
      goto leave;
    }
  }

  account->rights |= cap;
  account->rights &= ~ncap;

  /* warn if rights could not be successfully deleted. */
  if (account->classp->rights & ncap) {
    bf_printf (output, _("Warning! User %s is still awarded the following rights by his group:"),
	       account->nick);
    flags_print ((Capabilities + CAP_PRINT_OFFSET), output, ncap & account->classp->rights);
  }


  bf_printf (output, _("User %s with group %s.\nCurrent rights:"), account->nick,
	     account->classp->name);
  flags_print ((Capabilities + CAP_PRINT_OFFSET), output,
	       account->rights | account->classp->rights);
  bf_strcat (output, "\n");
  if (plugin_user_find (argv[1]))
    bf_printf (output,
	       _("User is already logged in. Tell him to rejoin to gain all his new rights.\n"));

leave:
  return 0;
}

unsigned long handler_userdel (plugin_user_t * user, buffer_t * output, void *priv,
			       unsigned int argc, unsigned char **argv)
{
  account_t *account;
  unsigned long long cap = 0;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick>"), argv[0]);
    return 0;
  }

  if (!(account = account_find (argv[1]))) {
    bf_printf (output, _("User account %s does not exist.\n"), argv[1]);
    goto leave;
  }
  if (!(user->rights & CAP_OWNER)) {
    cap = account->rights | account->classp->rights;
    if (cap & ~user->rights) {
      bf_printf (output, _("You are not allowed to delete user %s.\n"), argv[1]);
      goto leave;
    }
  }
  account_del (account);
  bf_printf (output, _("User account %s deleted.\n"), argv[1]);
  if (plugin_user_find (argv[1]))
    bf_printf (output,
	       _
	       ("User is still logged in with all rights of the deleted account. Kick the user to take them away.\n"));

leave:
  return 0;
}

unsigned long handler_userinfo (plugin_user_t * user, buffer_t * output, void *priv,
				unsigned int argc, unsigned char **argv)
{
  account_t *account = NULL;
  struct in_addr in;
  plugin_user_t *target;
  int cc;

  if (argc < 2) {
    bf_printf (output, _("Usage: %s <nick>"), argv[0]);
    return 0;
  }

  target = plugin_user_find (argv[1]);

  /* first check for hidden users: only the owner gets to see them */
  if (target && (target->rights & CAP_HIDDEN) && (!(user->rights & CAP_OWNER)))
    target = NULL;

  /* do output */
  if (!target) {
    bf_printf (output, _("User %s not found."), argv[1]);
  } else {
    bf_printf (output, _("User information for user %s\n"), target->nick);
  };

  if ((account = account_find (argv[1]))) {
    bf_printf (output, _("Group %s, Rights: "), account->classp->name);
    flags_print ((Capabilities + CAP_PRINT_OFFSET), output,
		 target ? target->rights : account->rights | account->classp->rights);
    bf_strcat (output, "\n");
    if (!account->passwd[0])
      bf_printf (output, _("Users password is NOT set.\n"));
    bf_printf (output, _("User was registered by %s on %s"), account->op, ctime (&account->regged));
    /* eat newline */
    if (output->e[-1] == '\n') {
      output->e[-1] = 0;
      --output->e;
    }
    if (account->lastlogin) {
      in.s_addr = account->lastip;
      bf_printf (output, _(", last login %s from %s"), ctime (&account->lastlogin), inet_ntoa (in));
#ifdef GEOIP
      cc = GeoIP_id_by_ipnum (gi, htonl (account->lastip));
      bf_printf (output, " (%s)", GeoIP_country_code[cc]);
#endif
      bf_printf (output, "\n");
    } else {
      bf_printf (output, _(", never logged in.\n"));
    }
  }

  if (target) {
    in.s_addr = target->ipaddress;
    bf_printf (output, _("Using Client %s version %s\n"), target->client, target->versionstring);
#ifndef USE_WINDOWS
    if (target->active) {
      bf_printf (output, "Client claims to be active and is sharing %s (%llu bytes)\n",
		 format_size (target->share), target->share);
    } else {
      bf_printf (output, "Client claims to be passive and is sharing %s (%llu bytes)\n",
		 format_size (target->share), target->share);
    }
#else
    if (target->active) {
      bf_printf (output, "Client claims to be active and is sharing %s (%I64u bytes)\n",
		 format_size (target->share), target->share);
    } else {
      bf_printf (output, "Client claims to be passive and is sharing %s (%I64u bytes)\n",
		 format_size (target->share), target->share);
    }
#endif
    bf_printf (output, _("IP: %s Hubs: (%u, %u, %u), Slots %u\n"), inet_ntoa (in), target->hubs[0],
	       target->hubs[1], target->hubs[2], target->slots);
#ifdef GEOIP
    cc = GeoIP_id_by_ipnum (gi, htonl (target->ipaddress));
    if (cc) {
      bf_printf (output, _("IP location %s (%s)\n"), GeoIP_country_name[cc],
		 GeoIP_country_code[cc]);
    } else {
      bf_printf (output, _("IP location unknown\n"));
    }
#endif
  };

  return 0;
}

unsigned long handler_usergroup (plugin_user_t * user, buffer_t * output, void *priv,
				 unsigned int argc, unsigned char **argv)
{
  account_t *account = NULL;
  account_type_t *group = NULL, *old;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <nick> <group>"), argv[0]);
    return 0;
  }

  if (!(account = account_find (argv[1]))) {
    bf_printf (output, _("User %s not found."), argv[1]);
    return 0;
  }

  if (!(group = account_type_find (argv[2]))) {
    bf_printf (output, _("Group %s does not exist."), argv[2]);
    return 0;
  }

  if (!(user->rights & CAP_OWNER)) {
    if (account->classp->rights & ~user->rights) {
      bf_printf (output, _("You are not allowed to remove a user from this group.\n"));
      return 0;
    }
    if (group->rights & ~user->rights) {
      bf_printf (output, _("You are not allowed to assign a user to this group.\n"));
      return 0;
    }
  }

  /* move to new group */
  old = account->classp;
  account->class = group->id;
  account->classp->refcnt--;
  account->classp = group;
  group->refcnt++;

  bf_printf (output, _("Moved user %s from group %s to %s\n"), account->nick, old->name,
	     group->name);

  return 0;
}

unsigned long handler_passwd (plugin_user_t * user, buffer_t * output, void *priv,
			      unsigned int argc, unsigned char **argv)
{
  account_t *account = NULL;
  unsigned char *passwd;
  plugin_user_t *bad;

  if (argc < 2) {
    bf_printf (output,
	       _
	       ("Usage: %s [<nick>] <password>\n If no nick is specified, your own password is changed."),
	       argv[0]);
    return 0;
  }

  if (argc > 2) {
    account = account_find (argv[1]);
    if (!account) {
      bf_printf (output, _("User %s not found."), argv[1]);
      goto leave;
    }
    passwd = argv[2];

    if (!(user->rights & CAP_USER) || (user->rights <= account->rights)) {
      bf_printf (output, _("You are not allowed to change %s\'s password\n"), account->nick);
      goto leave;
    }
  } else {
    passwd = argv[1];
    account = account_find (argv[1]);
    if (account) {
      bf_printf (output,
		 _
		 ("The password is unacceptable, please choose another. You specified a known account name as your password.\n"));
      goto leave;
    }
    bad = plugin_user_find (argv[1]);
    if (bad) {
      bf_printf (output,
		 _
		 ("The password is unacceptable, please choose another. You specified a logged in username as your password.\n"));
      goto leave;
    }
    account = account_find (user->nick);
    if (!account) {
      bf_printf (output, _("No account for user %s.\n"), user->nick);
      goto leave;
    }
  }


  if ((strlen (passwd) < MinPwdLength) || (!strcmp (passwd, account->passwd))) {
    bf_printf (output,
	       _("The password is unacceptable, please choose another. Minimum length is %d\n"),
	       MinPwdLength);
    goto leave;
  }

  /* copy the password */
  account_pwd_set (account, passwd);
  bf_printf (output, _("Password set.\n"));
leave:
  return 0;
}

unsigned long handler_pwgen (plugin_user_t * user, buffer_t * output, void *priv,
			     unsigned int argc, unsigned char **argv)
{
  account_t *account = NULL;
  unsigned char passwd[PASSWDLENGTH + 1];
  plugin_user_t *target;
  unsigned int i;
  buffer_t *message;

  if ((argc < 1) || (argc > 2)) {
    bf_printf (output,
	       _("Usage: %s [<nick>]\n If no nick is specified, your own password is changed."),
	       argv[0]);
    return 0;
  }

  if (argc > 1) {
    account = account_find (argv[1]);
    if (!account) {
      bf_printf (output, _("User %s not found."), argv[1]);
      goto leave;
    }

    if (!(user->rights & CAP_USER) || (user->rights <= account->rights)) {
      bf_printf (output, _("You are not allowed to change %s\'s password\n"), account->nick);
      goto leave;
    }

    target = plugin_user_find (argv[1]);
  } else {
    account = account_find (user->nick);
    if (!account) {
      bf_printf (output, _("No account for user %s.\n"), user->nick);
      goto leave;
    }
    target = user;
  }

  for (i = 0; i < (PASSWDLENGTH); i++) {
    passwd[i] = (40 + (random () % 82));
  }
  passwd[i] = '\0';

  if (target) {
    message = bf_alloc (1024);
    bf_printf (message, _("Your password was reset. It is now\n%.*s\n"), PASSWDLENGTH, passwd);
    plugin_user_priv (NULL, target, NULL, message, 1);
    bf_free (message);
  } else {
    bf_printf (output, _("The password of %s was reset. It is now\n%.*s\n"), argv[1], PASSWDLENGTH,
	       passwd);
  }

  /* copy the password */
  account_pwd_set (account, passwd);
  bf_printf (output, _("Password set.\n"));
leave:
  return 0;
}

#ifdef ENABLE_NLS
unsigned long handler_setlocale (plugin_user_t * user, buffer_t * output, void *priv,
				 unsigned int argc, unsigned char **argv)
{
  if (argc < 2) {
    bf_printf (output, "Usage: %s <local>", argv[0]);
    return 0;
  }

  /* Change language.  */
  setenv ("LANGUAGE", argv[1], 1);
  bf_printf (output, "Locale set to %s", argv[1]);

  /* Make change known.  */
  {
    extern int _nl_msg_cat_cntr;

    ++_nl_msg_cat_cntr;
  }

  return 0;
}

unsigned long handler_getlocale (plugin_user_t * user, buffer_t * output, void *priv,
				 unsigned int argc, unsigned char **argv)
{
  struct lconv *lconv;
  char *env, *var;

  var = "LANGUAGE";
  env = getenv (var);
  if (!env) {
    var = "LC_ALL";
    env = getenv (var);
  }
  if (!env) {
    var = "LC_MESSAGES";
    env = getenv (var);
  }
  if (!env) {
    var = "LANG";
    env = getenv (var);
  }

  if (var && env)
    bf_printf (output, _("Local is determined by variable %s and set to %s\n"), var, env);

  bf_printf (output, _("Locale is set to %s\n"), setlocale (LC_MESSAGES, NULL));

  lconv = localeconv ();
  if (*lconv->decimal_point != '.')
    bf_printf (output,
	       _
	       ("WARNING: decimal point is '%c', this will cause problems in parsing tags. Set LC_NUMERIC to \"C\""));

  return 0;
}
#endif

#ifdef DEBUG
#include "stacktrace.h"
unsigned long handler_crash (plugin_user_t * user, buffer_t * output, void *priv,
			     unsigned int argc, unsigned char **argv)
{
  ASSERT (0);
  return 0;
}
#endif

unsigned long handler_bug (plugin_user_t * user, buffer_t * output, void *priv,
			   unsigned int argc, unsigned char **argv)
{
  strcpy ((void *) 1L, "");
  return 0;
}

//#endif

/************************** config ******************************/

#include "config.h"
extern value_collection_t *configvalues;

int printconfig (buffer_t * buf, config_element_t * elem)
{
  switch (elem->type) {
    case CFG_ELEM_PTR:
      bf_printf (buf, "%s %p\n", elem->name, *elem->val.v_ptr);
      break;
    case CFG_ELEM_LONG:
      bf_printf (buf, "%s %ld\n", elem->name, *elem->val.v_long);
      break;
    case CFG_ELEM_ULONG:
      bf_printf (buf, "%s %lu\n", elem->name, *elem->val.v_ulong);
      break;
    case CFG_ELEM_ULONGLONG:
#ifndef USE_WINDOWS
      bf_printf (buf, "%s %llu\n", elem->name, *elem->val.v_ulonglong);
#else
      bf_printf (buf, "%s %I64u\n", elem->name, *elem->val.v_ulonglong);
#endif
      break;
    case CFG_ELEM_CAP:
      bf_printf (buf, "%s ", elem->name);
      flags_print ((Capabilities + CAP_PRINT_OFFSET), buf, *elem->val.v_cap);
      bf_strcat (buf, "\n");
      break;
    case CFG_ELEM_INT:
      bf_printf (buf, "%s %d\n", elem->name, *elem->val.v_int);
      break;
    case CFG_ELEM_UINT:
      bf_printf (buf, "%s %u\n", elem->name, *elem->val.v_int);
      break;
    case CFG_ELEM_DOUBLE:
      bf_printf (buf, "%s %lf\n", elem->name, *elem->val.v_double);
      break;
    case CFG_ELEM_STRING:
      bf_printf (buf, "%s \"%s\"\n", elem->name,
		 *elem->val.v_string ? *elem->val.v_string : (unsigned char *) "(NULL)");
      break;
    case CFG_ELEM_IP:
      {
	struct in_addr ia;

	ia.s_addr = *elem->val.v_ip;
	bf_printf (buf, "%s %s\n", elem->name, inet_ntoa (ia));
      }
      break;
    case CFG_ELEM_MEMSIZE:
      bf_printf (buf, "%s %s\n", elem->name, format_size (*elem->val.v_ulong));
      break;
    case CFG_ELEM_BYTESIZE:
      bf_printf (buf, "%s %s\n", elem->name, format_size (*elem->val.v_ulonglong));
      break;
    default:
      bf_printf (buf, _("%s !Unknown Type!\n"), elem->name);
  }
  return 0;
}

unsigned long handler_configshow (plugin_user_t * user, buffer_t * output, void *priv,
				  unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  config_element_t *elem;

  if (argc < 2) {
    for (elem = configvalues->value_sorted.onext; elem != &configvalues->value_sorted;
	 elem = elem->onext)
      printconfig (output, elem);
  } else {
    for (i = 1; i < argc; i++) {
      elem = config_find (argv[i]);
      if (!elem) {
	bf_printf (output, _("Sorry, unknown configuration value %s\n"), argv[i]);
	continue;
      }
      printconfig (output, elem);
    }
  };

  return 0;
}

unsigned long handler_confighelp (plugin_user_t * user, buffer_t * output, void *priv,
				  unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  config_element_t *elem;

  if (argc < 2) {
    for (elem = configvalues->value_sorted.onext; elem != &configvalues->value_sorted;
	 elem = elem->onext) {
      if (bf_unused (output) < (strlen (elem->name) + strlen (elem->help) + 4)) {
	buffer_t *buf;

	buf = bf_alloc (4000);
	bf_append (&output, buf);
	output = buf;
      }
      bf_printf (output, "%s: %s\n", elem->name, elem->help);
    }
  } else {
    for (i = 1; i < argc; i++) {
      elem = config_find (argv[i]);
      if (!elem) {
	bf_printf (output, _("Sorry, unknown configuration value %s\n"), argv[i]);
	continue;
      }
      if (bf_unused (output) < (strlen (elem->name) + strlen (elem->help) + 4)) {
	buffer_t *buf;

	buf = bf_alloc (4000);
	bf_append (&output, buf);
	output = buf;
      }
      bf_printf (output, "%s: %s\n", elem->name, elem->help);
    }
  };

  return 0;
}

unsigned long handler_configset (plugin_user_t * user, buffer_t * output, void *priv,
				 unsigned int argc, unsigned char **argv)
{
  unsigned long long cap = 0, ncap = 0;
  config_element_t *elem;

  if (argc < 3) {
    bf_printf (output, _("Usage: %s <setting> <value>"), argv[0]);
    return 0;
  }

  elem = config_find (argv[1]);
  if (!elem) {
    bf_printf (output, _("Sorry, unknown configuration value %s\n"), argv[1]);
    goto leave;
  }

  bf_printf (output, "Old: ");
  printconfig (output, elem);
  switch (elem->type) {
    case CFG_ELEM_PTR:
      sscanf (argv[2], "%p", elem->val.v_ptr);
      break;
    case CFG_ELEM_LONG:
      sscanf (argv[2], "%ld", elem->val.v_long);
      break;
    case CFG_ELEM_ULONG:
      sscanf (argv[2], "%lu", elem->val.v_ulong);
      break;
    case CFG_ELEM_ULONGLONG:
#ifndef USE_WINDOWS
      sscanf (argv[2], "%Lu", elem->val.v_ulonglong);
#else
      sscanf (argv[2], "%I64u", elem->val.v_ulonglong);
#endif
      break;
    case CFG_ELEM_CAP:
      if (!(user->rights & CAP_INHERIT)) {
	bf_printf (output, _("You are not allowed to assign rights.\n"));
	break;
      }
      flags_parse (Capabilities, output, argc, argv, 2, &cap, &ncap);
      if (!(user->rights & CAP_OWNER)) {
	if (cap & ~user->rights) {
	  bf_printf (output, _("You are not allowed to assign: "));
	  flags_print ((Capabilities + CAP_PRINT_OFFSET), output, cap & ~user->rights);
	  bf_strcat (output, "\n");
	  break;
	}
	if (ncap & ~user->rights) {
	  bf_printf (output, _("You are not allowed to remove: "));
	  flags_print ((Capabilities + CAP_PRINT_OFFSET), output, ncap & ~user->rights);
	  bf_strcat (output, "\n");
	  break;
	}
      }
      *elem->val.v_cap |= cap;
      *elem->val.v_cap &= ~ncap;
      break;
    case CFG_ELEM_INT:
      sscanf (argv[2], "%d", elem->val.v_int);
      break;
    case CFG_ELEM_UINT:
      sscanf (argv[2], "%u", elem->val.v_uint);
      break;
    case CFG_ELEM_DOUBLE:
      sscanf (argv[2], "%lf", elem->val.v_double);
      break;
    case CFG_ELEM_STRING:
      if (*elem->val.v_string)
	free (*elem->val.v_string);
      *elem->val.v_string = strdup (argv[2]);
      break;
    case CFG_ELEM_IP:
      {
	struct in_addr ia;

	if (!inet_aton (argv[2], &ia)) {
	  bf_printf (output, _("\"%s\" is not a valid IP address.\n"), argv[2]);
	  break;
	}
	*elem->val.v_ip = ia.s_addr;
      }
      break;
    case CFG_ELEM_MEMSIZE:
      {
	unsigned long long tmp = parse_size (argv[2]);

	if (tmp > LONG_MAX) {
	  bf_printf (output, _("The maximum value for this element is %s\n"),
		     format_size (LONG_MAX));
	  break;
	}
	*elem->val.v_ulong = tmp;
      }
      break;
    case CFG_ELEM_BYTESIZE:
      *elem->val.v_ulonglong = parse_size (argv[2]);
      break;
    default:
      bf_printf (output, _("%s !Unknown Type!\n"), elem->name);
  }

  if (plugin_user_event (user, PLUGIN_EVENT_CONFIG, elem) != PLUGIN_RETVAL_CONTINUE) {
    bf_printf (output, _("Configuration change denied.\n"));
  }

  bf_printf (output, "New: ");
  printconfig (output, elem);


leave:
  return 0;
}

#include "stats.h"
unsigned long handler_stats (plugin_user_t * user, buffer_t * output, void *priv,
			     unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  stats_element_t *elem;

  if (argc < 2) {
    for (elem = statvalues->value_sorted.onext; elem != &statvalues->value_sorted;
	 elem = elem->onext)
      printconfig (output, elem);
  } else {
    for (i = 1; i < argc; i++) {
      elem = stats_find (argv[i]);
      if (!elem) {
	bf_printf (output, _("Sorry, unknown configuration value %s\n"), argv[i]);
	continue;
      }
      printconfig (output, elem);
    }
  };

  return 0;
}

unsigned long handler_statshelp (plugin_user_t * user, buffer_t * output, void *priv,
				 unsigned int argc, unsigned char **argv)
{
  unsigned int i;
  config_element_t *elem;

  if (argc < 2) {
    for (elem = statvalues->value_sorted.onext; elem != &statvalues->value_sorted;
	 elem = elem->onext) {
      if (bf_unused (output) < (strlen (elem->name) + strlen (elem->help) + 4)) {
	buffer_t *buf;

	buf = bf_alloc (4000);
	bf_append (&output, buf);
	output = buf;
      }
      bf_printf (output, "%s: %s\n", elem->name, elem->help);
    }
  } else {
    for (i = 1; i < argc; i++) {
      elem = stats_find (argv[i]);
      if (!elem) {
	bf_printf (output, _("Sorry, unknown statistics value %s\n"), argv[i]);
	continue;
      }
      if (bf_unused (output) < (strlen (elem->name) + strlen (elem->help) + 4)) {
	buffer_t *buf;

	buf = bf_alloc (4000);
	bf_append (&output, buf);
	output = buf;
      }
      bf_printf (output, "%s: %s\n", elem->name, elem->help);
    }
  };

  return 0;
}


unsigned long handler_save (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			    unsigned char **argv)
{
  unsigned long retval = plugin_config_save (output);

  bf_printf (output, _("All Data saved."));

  /* reset autosave counter */
  if (AutoSaveInterval)
    savetime = now;

  return retval;
}
unsigned long handler_load (plugin_user_t * user, buffer_t * output, void *priv, unsigned int argc,
			    unsigned char **argv)
{
  unsigned long retval = plugin_config_load ();

  bf_printf (output, _("Data reloaded."));

  return retval;
}

unsigned long handler_autosave (plugin_user_t * user, void *ctxt, unsigned long event, void *token)
{
  buffer_t *output;
  unsigned int l;

  if (!AutoSaveInterval)
    return 0;

  if (now.tv_sec > (savetime.tv_sec + (time_t) AutoSaveInterval)) {
    savetime = now;
    output = bf_alloc (1024);
    bf_printf (output, _("Errors during autosave:\n"));
    l = bf_used (output);
    plugin_config_save (output);
    if (bf_used (output) != l) {
      plugin_report (output);
    }
    bf_free (output);
  }

  return 0;
}

/************************** INIT ******************************/

int builtincmd_init ()
{
  /* *INDENT-OFF* */
  MinPwdLength        = DEFAULT_MINPWDLENGTH;
  AutoSaveInterval    = DEFAULT_AUTOSAVEINTERVAL;
  ReportTarget      = strdup (DEFAULT_REPORTTARGET);
  KickMaxBanTime      = 0;
  KickNoBanMayBan      = 0;
  
  config_register ("MinPwdLength",     CFG_ELEM_UINT,   &MinPwdLength,     _("Minimum length of a password."));
  config_register ("AutoSaveInterval", CFG_ELEM_ULONG,  &AutoSaveInterval, _("Period for autosaving settings, set to 0 to disable."));
  config_register ("ReportTarget",     CFG_ELEM_STRING, &ReportTarget,     _("User to send report to. Can be a chatroom."));
  config_register ("kickmaxbantime",   CFG_ELEM_ULONG,  &KickMaxBanTime,   _("This is the maximum bantime you can give with a kick (and using _ban_). This does not affect someone with the ban right."));
  config_register ("kicknobanmayban",  CFG_ELEM_UINT,   &KickNoBanMayBan,  _("If set, then a user without the ban right can use _ban_ to ban anyway. The maximum time can be set with kickmaxbantime."));


  command_register ("say",        &handler_say,  	 CAP_SAY,     _("Make the HubSec say something."));
  command_register ("warn",       &handler_warn,  	 CAP_KEY,     _("Make the HubSec warn user."));
  command_register ("shutdown",	  &handler_shutdown,     CAP_OWNER,   _("Shut the hub down."));
  command_register ("report",     &handler_report,       0,           _("Send a report to the OPs."));
  command_register ("version",    &handler_version,      0,           _("Displays the Aquila version."));
  command_register ("myip",       &handler_myip,         0,           _("Shows you your IP address."));
  command_register ("kick",       &handler_kick,         CAP_KICK,    _("Kick a user. Automatic short ban included."));
  command_register ("drop",       &handler_drop,         CAP_KICK,    _("Drop a user. Automatic short ban included."));
  command_register ("banip",      &handler_banip,        CAP_BAN,     _("IP Ban a user by IP address."));
  command_register ("bannick",    &handler_bannick,      CAP_BAN,     _("Nick ban a user by nick."));
  command_register ("ban",        &handler_ban,          CAP_BAN,     _("Ban a user by nick."));
  command_register ("banlist",    &handler_banlist,      CAP_BAN,     _("Show ban by nick/IP."));
  command_register ("help",       &handler_help,         0,           _("Display help message."));
  command_register ("unban",      &handler_unban,        CAP_BAN,     _("Unban a nick."));
  command_register ("unbanip",    &handler_unbanip,      CAP_BAN,     _("Unban an ip."));
  command_register ("baniphard",  &handler_banhard,      CAP_BANHARD, _("Hardban an IP."));
  command_register ("unbaniphard",&handler_unbanip_hard, CAP_BANHARD, _("Unhardban an IP."));
  command_register ("hardbanlist",&handler_hardbanlist,  CAP_BANHARD, _("Show hard bans by nick/IP."));
  command_register ("zombie",     &handler_zombie,       CAP_KICK,    _("Zombie a user. Can't talk or pm."));
  command_register ("zombielist", &handler_zombielist,   CAP_KICK,    _("Show the zombie horde."));
  command_register ("unzombie",   &handler_unzombie,     CAP_KICK,    _("Unzombie a user. Can talk or pm again."));
  command_register ("whoip",      &handler_whoip,        CAP_KICK,    _("Returns the user using the IP."));

  command_register ("massall",	  &handler_massall,    CAP_CONFIG,     _("Send a private message to all users."));

  command_register ("rightcreate",  &handler_rightcreate,   CAP_ADMIN|CAP_INHERIT, _("Create a custom right."));
  command_register ("rightdestroy", &handler_rightdestroy,  CAP_ADMIN|CAP_INHERIT, _("Destroy a custom right."));

  command_register ("groupadd",   &handler_groupadd,   CAP_GROUP,     _("Add a user group."));
  command_register ("groupdel",   &handler_groupdel,   CAP_GROUP,     _("Delete a user group."));
  command_register ("grouprights",&handler_groupcap,   CAP_GROUP,     _("Edit the rights of a user group."));
  command_register ("grouplist",  &handler_grouplist,  CAP_GROUP,     _("List all groups with their rights."));

  command_register ("useradd",    &handler_useradd,    CAP_USER,      _("Add a user."));
  command_register ("userdel",    &handler_userdel,    CAP_USER,      _("Delete a user."));
  command_register ("userrights", &handler_usercap,    CAP_USER|CAP_INHERIT,  _("Edit the extra rights of a user."));
  command_register ("userlist",   &handler_userlist,   CAP_USER,      _("List all users of a user group."));
  command_register ("userinfo",   &handler_userinfo,   CAP_KICK,      _("Show information of user."));
  command_register ("usergroup",  &handler_usergroup,  CAP_USER,      _("Move user to new group. Reconnect for change to activate."));

  command_register ("configshow", &handler_configshow, CAP_CONFIG,    _("Show configuration."));
  command_register ("confighelp", &handler_confighelp, CAP_CONFIG,    _("Show configuration value help string."));
  command_register ("configset",  &handler_configset,  CAP_CONFIG,    _("Set configuration values."));
  command_register ("=",	      &handler_configset,  CAP_CONFIG,    _("Set configuration values."));

  command_register ("stats",      &handler_stats,      CAP_CONFIG,    _("Show raw statistics."));
  command_register ("statshelp",  &handler_statshelp,  CAP_CONFIG,    _("Show statistics help."));

  command_register ("load",       &handler_load,       CAP_CONFIG,    _("Reload all data from files. WARNING: All unsaved changes will be discarded."));
  command_register ("save",       &handler_save,       CAP_CONFIG,    _("Save all changes to file. WARNING: All previously saved settings will be lost!"));
  
  command_register ("passwd",     &handler_passwd,	0,            _("Change your password."));
  command_register ("pwgen",      &handler_pwgen,	0,            _("Let the hub generate a random password."));

#ifdef ENABLE_NLS
  command_register ("setlocale",  &handler_setlocale,	CAP_ADMIN,    _("Set the locale of the hub."));
  command_register ("getlocale",  &handler_getlocale,	CAP_ADMIN,    _("Get the locale of the hub."));
#endif

#ifdef DEBUG
  command_register ("crash",      &handler_crash,	CAP_OWNER,    _("Let the hub CRASH!."));
#endif
  command_register ("bug",	  &handler_bug,		CAP_OWNER,    _("Let the hub CRASH!."));
  gettimeofday (&savetime, NULL);
  
  plugin_request (NULL, PLUGIN_EVENT_CACHEFLUSH, (plugin_event_handler_t *)handler_autosave);

  /* *INDENT-ON* */

#ifdef GEOIP
  gi = GeoIP_new (GEOIP_MEMORY_CACHE);
  //gi = GeoIP_new (GEOIP_STANDARD);
#endif

  return 0;
}
