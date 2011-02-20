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

#ifndef _CAP_H_
#define _CAP_H_

#include "flags.h"
#include "xml.h"

#define CAP_SHARE  	   0x0001LL
#define CAP_KICK   	   0x0002LL
#define CAP_BAN    	   0x0004LL
#define CAP_KEY    	   0x0008LL
#define CAP_CONFIG 	   0x0010LL
#define CAP_SAY    	   0x0020LL
#define CAP_USER   	   0x0040LL
#define CAP_GROUP  	   0x0080LL
#define CAP_INHERIT	   0x0100LL
#define CAP_CHAT   	   0x0200LL
#define CAP_PM     	   0x0400LL
#define CAP_DL	   	   0x0800LL
#define CAP_BANHARD	   0x1000LL
#define CAP_SEARCH	   0x2000LL
#define CAP_PMOP	   0x4000LL
#define CAP_TAG		   0x8000LL
#define CAP_SHAREHIDE	  0x10000LL
#define CAP_SHAREBLOCK	  0x20000LL
#define CAP_SPAM	  0x40000LL
#define CAP_NOSRCHLIMIT   0x80000LL
#define CAP_SOURCEVERIFY 0x100000LL
#define CAP_REDIRECT     0x200000LL
#define CAP_LOCALLAN     0x400000LL
#define CAP_HIDDEN	 0x800000LL
#define CAP_OWNER	0x1000000LL

#define CAP_PRINT_OFFSET 	7

/* custom rights availability */
#define CAP_CUSTOM_OFFSET 	32
#define CAP_CUSTOM_MAX		72
#define CAP_CUSTOM_FIRST	25
#define CAP_CUSTOM_MASK  0xFFFFFFFFFE000000LL

/* shortcuts... */
#define CAP_DEFAULT (CAP_CHAT | CAP_PMOP | CAP_DL | CAP_SEARCH)
#define CAP_REG   (CAP_DEFAULT | CAP_PM)
#define CAP_VIP	  (CAP_REG  | CAP_SHARE | CAP_SPAM)
#define CAP_KVIP  (CAP_VIP  | CAP_KICK)
#define CAP_OP    (CAP_KVIP | CAP_BAN | CAP_KEY | CAP_NOSRCHLIMIT | CAP_REDIRECT)
#define CAP_CHEEF (CAP_OP   | CAP_USER)
#define CAP_ADMIN (CAP_CHEEF | CAP_CONFIG | CAP_INHERIT | CAP_GROUP)

extern flag_t Capabilities[];

extern flag_t *cap_custom_add (unsigned char *name, unsigned char *help);
extern int cap_custom_remove (unsigned char *name);

extern int cap_save (xml_node_t *);

#endif
