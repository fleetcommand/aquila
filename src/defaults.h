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

#ifndef _DEFAULTS_H_
#define _DEFAULTS_H_

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#ifdef USE_WINDOWS
#undef HAVE_ARPA_INET_H
#undef HAVE_SYS_SOCKET_H
#undef HAVE_NETINET_IN_H
#undef HAVE_SYS_POLL_H

#define WIN32TAG	" Win32"

#else
#define WIN32TAG

#endif


#ifdef SVNREVISION
#define AQUILA_VERSION			VERSION " (" SVNREVISION ")"
#else
#define AQUILA_VERSION			VERSION WIN32TAG
#endif

#define HUBSOFT_NAME		"Aquila"
#define HUBSOFT_HOMEPAGE	"http://aquiladc.sourceforge.net/"
#define HUBSOFT_AUTHOR		"Johan Verrept"
/*
 * These values determine the size and mask of the configuration value
 *   hash tables.
 * CONFIG_NAMELENGTH determines the max namelength of a config value.
 */

#define CONFIG_HASHSIZE		32
#define CONFIG_HASHMASK		(CONFIG_HASHSIZE - 1)
#define CONFIG_NAMELENGTH	64

/*
 *  Determine the Lock string and the length of the random data in the lock.
 */
#define LOCK	 HUBSOFT_NAME
#define LOCKLENGTH 4

/*
 * Default hubname, description and owner
 */

#define HUBNAME  "Capitol"
#define HUBDESC  "Licat volare si super tergum Aquila volat."
#define HUBOWNER "Unknown"

/*
 * These are generic settings in the hub. modifying them can influence memory usage.
 */
#define NICKLENGTH  64
#define PASSWDLENGTH 8
#define BUFSIZE 65536
#define MAX_TOKEN_SIZE 65535

/*
 *  Buffering defaults. 
 */
#define DEFAULT_BUFFER_SOFTLIMIT    40*1024
#define DEFAULT_BUFFER_HARDLIMIT    100*1024
#define DEFAULT_BUFFER_TOTALLIMIT    100*1024*1024
#define DEFAULT_OUTGOINGTHRESHOLD   1000

#define DEFAULT_TIMEOUT_BUFFERING   30000
#define DEFAULT_TIMEOUT_OVERFLOW    10000

/*
 * Research stuff
 */
#define DEFAULT_RESEARCH_MININTERVAL	60
#define DEFAULT_RESEARCH_PERIOD		7200
#define DEFAULT_RESEARCH_MAXCOUNT	120

/*
 * Default settings for listening port, ip and address.
 */
#define DEFAULT_PORT	      411
#define DEFAULT_IP	      0L
#define DEFAULT_ADDRESS	      "localhost"
#define NMDC_EXTRA_PORTS      ""

/*
 * Hub security defaults.
 */

#define DEFAULT_HUBSECURITY_NICK     		"Aquila"
#define DEFAULT_HUBSECURITY_DESCRIPTION		"His attribute is the lightning bolt and the eagle is both his symbol and his messenger."

/*
 * Filenames of the core savefiles.
 */
#define DEFAULT_SAVEFILE        "hub.conf"
#define DEFAULT_HARDBANFILE	"hardban.conf"
#define DEFAULT_SOFTBANFILE	"softban.conf"
#define DEFAULT_ACCOUNTSFILE	"accounts.conf"

#define DEFAULT_REDIRECT	""

/*
 * Where to send reports...
 */
#define DEFAULT_REPORTTARGET	""
#define DEFAULT_SYSREPORTTARGET ""

/*
 * Default TAG field length settings
 */

#define DEFAULT_MAXDESCRIPTIONLENGTH	11
#define DEFAULT_MAXTAGLENGTH		50
#define DEFAULT_MAXSPEEDLENGTH		10
#define DEFAULT_MAXEMAILLENGTH		50
#define DEFAULT_MAXSHARELENGTH		13	/* should be in the PetaByte range */
#define DEFAULT_DROPONTAGTOOLONG	1

/*
 * More settings...
 */

#define DEFAULT_KICKPERIOD		300

#define DEFAULT_AUTOSAVEINTERVAL	300

#define DEFAULT_MINPWDLENGTH		4

#define DEFAULT_MAXCHATLENGTH		512
#define DEFAULT_MAXSEARCHLENGTH		512
#define DEFAULT_MAXSRLENGTH		512
#define DEFAULT_CLONING			0

#define DEFAULT_MAXLUASCRIPTS		25

#define DEFAULT_PASSWDRETRY		3
#define DEFAULT_PASSWDBANTIME		300

#define DEFAULT_RECONNECTBANTIME	120

#define DEFAULT_CTMBANTIME		3600

#define DEFAULT_DELAYEDLOGOUT		10
#define DEFAULT_DELAYEDLOGOUTMAX	100

#define DEFAULT_VIOLATIONBANTIME	3600
#define DEFAULT_PROBATIONPERIOD		60

#define BANLIST_HASHBITS	11
#define BANLIST_HASHSIZE	(1 << BANLIST_HASHBITS)
#define BANLIST_HASHMASK	(BANLIST_HASHSIZE-1)

#define BANLIST_NICK_HASHBITS   11
#define BANLIST_NICK_HASHSIZE	(1 << BANLIST_NICK_HASHBITS)
#define BANLIST_NICK_HASHMASK	(BANLIST_NICK_HASHSIZE-1)


#define BANLIST_CLIENT_HASHBITS   10
#define BANLIST_CLIENT_HASHSIZE	(1 << BANLIST_NICK_HASHBITS)
#define BANLIST_CLIENT_HASHMASK	(BANLIST_NICK_HASHSIZE-1)

#define IPLIST_HASHBITS   10
#define IPLIST_HASHSIZE   (1 << IPLIST_HASHBITS)
#define IPLIST_HASHMASK	  (IPLIST_HASHSIZE-1)

#define IPLIST_SIZE	8096
#define IPLIST_TIME	30

#define DEFAULT_NICKCHARS ""

/*
 * Fork storm prevention: minimum second delay between forks
 */
 
#define MIN_FORK_RETRY_PERIOD		3

#ifdef DEBUG
#include <stdio.h>
#include "stacktrace.h"
#define DPRINTF	printf
//#define ASSERT assert
#define ASSERT(expr) ( (void)( (expr) ? 0 : (DPRINTF ("ASSERT FAILED (%s:%d): " #expr, __FILE__, __LINE__), fflush (stdout), CrashHandler(-1)) ) )
#else
#define DPRINTF(x...) /* x */
#define ASSERT(x...) /* x */
#endif

#include "gettext.h"

#endif /* _DEFAULTS_H_ */
