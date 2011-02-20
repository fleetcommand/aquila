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

#ifndef _CORE_CONFIG_H_
#define _CORE_CONFIG_H_

#include "defaults.h"

typedef struct {
  /* hub data */
  unsigned int ListenPort;
  unsigned long ListenAddress;
  unsigned char *NMDCExtraPorts;
  unsigned char *HubName;
  unsigned char *HubDesc;
  unsigned char *HubOwner;
  unsigned char *Hostname;
  unsigned char *HubSecurityNick;
  unsigned char *HubSecurityDesc;

  /* protocol settings */
  unsigned int MaxDescriptionLength;
  unsigned int MaxTagLength;
  unsigned int MaxSpeedLength;
  unsigned int MaxEMailLength;
  unsigned int MaxShareLength;
  unsigned int DropOnTagTooLong;

  /* user specific settings */
  unsigned long long DefaultRights;
  unsigned long defaultKickPeriod;

  /* more settings */
  unsigned char *Redirect;
  unsigned char *KickBanRedirect;
  unsigned char *SysReportTarget;
  
  /* buffering settings */
  unsigned long BufferSoftLimit;
  unsigned long BufferHardLimit;
  unsigned long BufferTotalLimit;

  unsigned long TimeoutBuffering;
  unsigned long TimeoutOverflow;

  unsigned long PasswdRetry;
  unsigned long PasswdBantime;

  unsigned long ReconnectBantime;
  unsigned long CTMBantime;

  unsigned long ProbationPeriod;
  unsigned long ViolationBantime;

  unsigned long DelayedLogout;
  // NI unsigned long DelayedLogoutMax;
} config_t;

extern config_t config;

extern int core_config_init ();

#endif /* _CORE_CONFIG_H_ */
