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

#ifndef _USER_H_
#define _USER_H_

#include "config.h"

typedef struct account_type {
  struct account_type *next, *prev;

  unsigned char name[NICKLENGTH];
  unsigned long long rights;
  unsigned int id;

  unsigned long refcnt;
} account_type_t;

typedef struct account {
  struct account *next, *prev;

  unsigned char nick[NICKLENGTH];
  unsigned char passwd[NICKLENGTH];
  unsigned char op[NICKLENGTH];
  unsigned long long rights;
  unsigned int class;
  unsigned long id;

  unsigned int refcnt;		/* usually 1 or 0 : user is logged in or not */
  time_t	regged;
  time_t	lastlogin;
  unsigned long	lastip;

  unsigned int	badpw;

  account_type_t *classp;
} account_t;

extern account_type_t *account_type_add (unsigned char *name, unsigned long long rights);
extern account_type_t *account_type_find (unsigned char *name);
extern unsigned int account_type_del (account_type_t *);
extern account_type_t *account_type_find_byid (unsigned long id);

extern account_t *account_add (account_type_t * type, unsigned char *op, unsigned char *nick);
extern account_t *account_find (unsigned char *nick);
extern unsigned int account_set_type (account_t * a, account_type_t * new);
extern unsigned int account_del (account_t * a);

extern int account_pwd_set (account_t * account, unsigned char *pwd);
extern int account_pwd_check (account_t * account, unsigned char *pwd);

extern unsigned int accounts_load (xml_node_t *);
extern unsigned int accounts_save (xml_node_t *);

extern unsigned int accounts_init ();

#endif
