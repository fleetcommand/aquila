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

#ifndef _HASHLIST_FUNC_H_
#define _HASHLIST_FUNC_H_

#include "hashlist.h"

void hash_init (hashlist_t * list);

unsigned int hash_adduser (hashlist_t * list, user_t *);
void hash_deluser (hashlist_t * list, hashlist_entry_t *);

extern user_t *hash_find_nick (hashlist_t * list, unsigned char *n, unsigned int len);
extern user_t *hash_find_ip (hashlist_t * list, unsigned long ip);
extern user_t *hash_find_net (hashlist_t * list, unsigned long ip, unsigned long netmask);
extern user_t *hash_find_ip_next (hashlist_t * list, user_t *last, unsigned long ip);
extern user_t *hash_find_net_next (hashlist_t * list, user_t *last, unsigned long ip, unsigned long netmask);
#endif /* _HASHLIST_FUNC_H_ */
