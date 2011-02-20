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

#include "config.h"
#include "core_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "hash.h"
#include "cap.h"
#include "proto.h"
#include "iplist.h"
#include "stats.h"

#include "hub.h"

extern int ndelay;
extern unsigned int blockonoverflow;
extern unsigned int disconnectontimeout;

#ifdef USE_IOCP
extern unsigned long iocpFragments;
extern unsigned long iocpSendBuffer;
#endif

config_t config;

int core_config_init ()
{
  /* *INDENT-OFF* */
  config.ListenPort      = DEFAULT_PORT;
  config.ListenAddress   = DEFAULT_IP;
  config.NMDCExtraPorts  = strdup (NMDC_EXTRA_PORTS);
  config.HubName         = strdup (HUBNAME);
  config.HubDesc         = strdup (HUBDESC);
  config.HubOwner        = strdup (HUBOWNER);
  config.Hostname        = strdup (DEFAULT_ADDRESS);
  config.HubSecurityNick = strdup (DEFAULT_HUBSECURITY_NICK);
  config.HubSecurityDesc = strdup (DEFAULT_HUBSECURITY_DESCRIPTION);

  config.MaxDescriptionLength = DEFAULT_MAXDESCRIPTIONLENGTH;
  config.MaxTagLength         = DEFAULT_MAXTAGLENGTH;
  config.MaxSpeedLength       = DEFAULT_MAXSPEEDLENGTH;
  config.MaxEMailLength       = DEFAULT_MAXEMAILLENGTH;
  config.MaxShareLength       = DEFAULT_MAXSHARELENGTH;
  config.DropOnTagTooLong     = DEFAULT_DROPONTAGTOOLONG;
  
  config.Redirect            = strdup (DEFAULT_REDIRECT);
  config.KickBanRedirect     = strdup (DEFAULT_REDIRECT);
  config.defaultKickPeriod   = DEFAULT_KICKPERIOD;
  config.SysReportTarget     = strdup (DEFAULT_SYSREPORTTARGET);

  config.BufferSoftLimit = DEFAULT_BUFFER_SOFTLIMIT;
  config.BufferHardLimit = DEFAULT_BUFFER_HARDLIMIT;
  config.BufferTotalLimit = DEFAULT_BUFFER_TOTALLIMIT;

  config.TimeoutBuffering = DEFAULT_TIMEOUT_BUFFERING;
  config.TimeoutOverflow = DEFAULT_TIMEOUT_OVERFLOW;
  
  config.DefaultRights = CAP_DEFAULT;

  config.PasswdRetry = DEFAULT_PASSWDRETRY;
  config.PasswdBantime = DEFAULT_PASSWDBANTIME;

  config.ReconnectBantime = DEFAULT_RECONNECTBANTIME;
  config.CTMBantime = DEFAULT_CTMBANTIME;

  config.ViolationBantime = DEFAULT_VIOLATIONBANTIME;
  config.ProbationPeriod = DEFAULT_PROBATIONPERIOD;

  config.DelayedLogout = DEFAULT_DELAYEDLOGOUT;

  config_register ("NMDC.ListenPort",    CFG_ELEM_UINT,   &config.ListenPort,      _("Port on which the hub will listen."));
  config_register ("NMDC.ListenAddress", CFG_ELEM_IP,     &config.ListenAddress,   _("IP on which the hub will listen, set to 0.0.0.0 for all."));
  config_register ("NMDC.ExtraPorts",    CFG_ELEM_STRING, &config.NMDCExtraPorts,  _("Extra NMDC ports to listen on."));
  config_register ("HubAddress",         CFG_ELEM_STRING, &config.Hostname,        _("A hostname (or IP address) where your machine will be reachable."));
  config_register ("HubName",            CFG_ELEM_STRING, &config.HubName,         _("Name of the hub"));
  config_register ("HubDescription",     CFG_ELEM_STRING, &config.HubDesc,         _("Description of the hub."));
  config_register ("HubOwner",           CFG_ELEM_STRING, &config.HubOwner,        _("Owner of the hub."));
  config_register ("HubSecurity.Nick",   CFG_ELEM_STRING, &config.HubSecurityNick, _("Name of the Hub Security bot."));
  config_register ("HubSecurity.Desc",   CFG_ELEM_STRING, &config.HubSecurityDesc, _("Description of the Hub Security bot."));

  config_register ("tag.MaxDescLength",    CFG_ELEM_UINT,   &config.MaxDescriptionLength, _("Maximum Length of the users description field."));
  config_register ("tag.MaxTagLength",     CFG_ELEM_UINT,   &config.MaxTagLength,    _("Maximum length of the users tag field."));
  config_register ("tag.MaxSpeedLength",   CFG_ELEM_UINT,   &config.MaxSpeedLength,  _("Maximum length of the users speed field."));
  config_register ("tag.MaxEMailLength",   CFG_ELEM_UINT,   &config.MaxEMailLength,  _("Maximum length of the users email address field."));
  config_register ("tag.MaxShareLength",   CFG_ELEM_UINT,   &config.MaxShareLength,  _("Maximum length of the users sharesize field."));
  config_register ("tag.DropOnTagTooLong", CFG_ELEM_UINT,   &config.DropOnTagTooLong, _("Kick the user if the tag is too long. If this is not set, the tag will be hidden."));
  
  config_register ("Redirect",           CFG_ELEM_STRING, &config.Redirect,        _("Redirection target."));
  config_register ("KickBanRedirect",    CFG_ELEM_STRING, &config.KickBanRedirect, _("Redirection target in case of kick or ban."));
  config_register ("KickAutoBanLength",  CFG_ELEM_ULONG,  &config.defaultKickPeriod, _("Length of automatic temporary ban after a kick."));

  config_register ("hub.PasswdRetries",  CFG_ELEM_ULONG,  &config.PasswdRetry, _("Maximum number of retries a user is allowed for his password."));
  config_register ("hub.PasswdBantime",  CFG_ELEM_ULONG,  &config.PasswdBantime, _("Length of automatic ban on too many retries (in seconds)."));

  config_register ("hub.ReconnectBantime",  CFG_ELEM_ULONG,  &config.ReconnectBantime, _("Users can only reconnect after this period (in seconds). This is counted from the previous login time, not logout."));
  config_register ("hub.CTMBantime",  CFG_ELEM_ULONG,  &config.CTMBantime, _("IPs that are used in a CTM exploit attack are hard banned for this time (in seconds)."));

  config_register ("hub.DelayedLogout",     CFG_ELEM_ULONG,  &config.DelayedLogout, _("Users that go offline for shorter than this period do not appear to go offline. On rejoing they will get their rate counters back."));

  config_register ("hub.SysReportTarget", CFG_ELEM_STRING, &config.SysReportTarget, _("The hub sends all error messages here."));

  config_register ("hub.BufferSoftLimit",     CFG_ELEM_MEMSIZE,  &config.BufferSoftLimit, _("If a user has more data buffered than this setting, he has limited time to read it all."));
  config_register ("hub.BufferHardLimit",     CFG_ELEM_MEMSIZE,  &config.BufferHardLimit, _("If a user has more data buffered than this setting, no more will be allowed."));
  config_register ("hub.BufferTotalLimit",     CFG_ELEM_MEMSIZE,  &config.BufferTotalLimit, _("If the hub is buffering more than this setting, no more will be allowed."));

  config_register ("hub.TimeoutBuffering",     CFG_ELEM_ULONG,  &config.TimeoutBuffering, _("If the hub start buffering for a user, after this many milliseconds, the user will be disconnected."));
  config_register ("hub.TimeoutOverflow",      CFG_ELEM_ULONG,  &config.TimeoutOverflow,  _("If the hub start buffering for a user and the amount exceed hub.BufferSoftLimit, he wil be disconnected after this many milliseconds."));

  config_register ("hub.ViolationBantime", CFG_ELEM_ULONG,  &config.ViolationBantime, _("If a user violates the rate controls too much, he will be banned for this amount of time."));
  config_register ("hub.ViolationProbationPeriod",  CFG_ELEM_ULONG,  &config.ProbationPeriod,  _("If the user violatest the rate controls too much within this period after joining, he will be hardbanned permanently."));

  config_register ("user.defaultrights",CFG_ELEM_CAP,  &config.DefaultRights,      _("These are the rights of an unregistered user."));

  config_register ("hub.reconnectperiod", CFG_ELEM_ULONG, &iplist_interval, _("This is the minimum time before an IP address is allowed to reconnect to the hub. NEVER TURN THIS OFF."));
  config_register ("hub.reconnectsize", CFG_ELEM_ULONG, &iplist_size, _("This is the number of IP address to remember."));

  config_register ("hub.ndelay", CFG_ELEM_UINT, &ndelay, _("This turns on or off the ndelay setting."));

  config_register ("hub.BufferBlockOnOverflow", CFG_ELEM_UINT, &blockonoverflow, _("This turns on or off input processing for users in overflow mode."));
  config_register ("hub.BufferDisconnectOnTimeout", CFG_ELEM_UINT, &disconnectontimeout, _("This turns on or off disconnecting users on buffering timeout."));

#ifdef USE_IOCP
  config_register ("socket.fragments", CFG_ELEM_ULONG, &iocpFragments, _("Maximum number of outstanding data buffers per user."));
  config_register ("socket.sendbuffer", CFG_ELEM_ULONG, &iocpSendBuffer, _("Set this to 0 to enable the send buffer."));
#endif
  /* *INDENT-ON* */

  return 0;
};

extern unsigned long buf_mem;

#ifdef USE_WINDOWS
extern unsigned long outstanding;
extern unsigned long outstanding_peak;
extern unsigned long outstanding_max;
extern unsigned long outstandingbytes;
extern unsigned long outstandingbytes_peak;
extern unsigned long outstandingbytes_max;
extern unsigned long iocp_users;
extern unsigned long outstandingbytes_peruser;

#endif

int core_stats_init ()
{
  stats_register ("hub.TotalBytesReceived", VAL_ELEM_ULONGLONG, &hubstats.TotalBytesReceived,
		  _("Total bytes send by hub since startup."));
  stats_register ("hub.TotalBytesSend", VAL_ELEM_ULONGLONG, &hubstats.TotalBytesSend,
		  _("Total bytes send by hub since startup."));
  stats_register ("hub.buffering", VAL_ELEM_ULONG, &buffering, _("Number of buffering users."));
  stats_register ("hub.buffermemory", VAL_ELEM_ULONG, &buf_mem,
		  _("Total of all data waiting to be written."));

#ifdef USE_WINDOWS
  stats_register ("iocp.outstanding", VAL_ELEM_ULONG, &outstanding,
		  _("Number of outstanding buffers."));
  stats_register ("iocp.outstanding_peak", VAL_ELEM_ULONG, &outstanding_peak,
		  _("Peak number of outstanding buffers."));
  stats_register ("iocp.outstanding_max", VAL_ELEM_ULONG, &outstanding_max,
		  _("Absolute maximum of outstanding buffers allowed."));

  stats_register ("iocp.outstandingbytes", VAL_ELEM_ULONG, &outstanding,
		  _("Number of outstanding buffers."));
  stats_register ("iocp.outstandingbytes_peak", VAL_ELEM_ULONG, &outstandingbytes_peak,
		  _("Peak number of outstanding bytes."));
  stats_register ("iocp.outstandingbytes_max", VAL_ELEM_ULONG, &outstandingbytes_max,
		  _("Absolute maximum of outstanding bytes allowed."));

  stats_register ("iocp_users", VAL_ELEM_ULONG, &iocp_users, _("Number of IOCP users."));
  stats_register ("outstandingbytes_peruser", VAL_ELEM_ULONG, &outstandingbytes_peruser,
		  _("Absolute maximum of outstanding bytes per user allowed."));
#endif
  return 0;
}
