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

#ifndef _UTILS_H_
#define _UTILS_H_

#ifndef __USE_W32_SOCKETS
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif
#  include <arpa/inet.h>
#else
#  include <winsock2.h>
#endif /* __USE_W32_SOCKETS */

#include "buffer.h"
extern unsigned char *format_size (unsigned long long size);
extern unsigned long long parse_size (unsigned char *token);
extern char * time_print (unsigned long s);
extern unsigned long time_parse (unsigned char *string);
extern unsigned long parse_ip (unsigned char *text, struct in_addr *ip, struct in_addr *netmask);
extern unsigned char *print_ip (struct in_addr ip, struct in_addr netmask);
extern unsigned char *string_unescape (unsigned char *in);
extern unsigned char *string_escape (unsigned char *in);

#endif /* _UTILS_H_ */
