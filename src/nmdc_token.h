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

#ifndef _TOKEN_H_
#define _TOKEN_H_

enum {
  TOKEN_UNIDENTIFIED = 0,
  TOKEN_CHAT,
  TOKEN_MYINFO,
  TOKEN_MYPASS,
  TOKEN_MYNICK,
  TOKEN_MULTISEARCH,
  TOKEN_MULTICONNECTTOME,
  TOKEN_SEARCH,
  TOKEN_SR,
  TOKEN_SUPPORTS,
  TOKEN_LOCK,
  TOKEN_KEY,
  TOKEN_KICK,
  TOKEN_HELLO,
  TOKEN_GETNICKLIST,
  TOKEN_GETINFO,
  TOKEN_CONNECTTOME,
  TOKEN_REVCONNECTOTME,
  TOKEN_TO,
  TOKEN_QUIT,
  TOKEN_OPFORCEMOVE,
  TOKEN_VALIDATENICK,
  TOKEN_BOTINFO,
  TOKEN_NUM
};

typedef struct token_definition {
  unsigned short num;
  unsigned short len;
  unsigned char *identifier;
} token_definition_t;

typedef struct token {
  unsigned short type;
  unsigned char *token, *argument;
} token_t;

extern struct token_definition Tokens[];

void token_init ();
int token_parse (struct token *token, unsigned char *string);

#endif /* _TOKEN_H_ */
