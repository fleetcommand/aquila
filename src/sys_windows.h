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

#ifndef _SYS_WINDOWS_H_
#define _SYS_WINDOWS_H_

#include <winsock2.h>

/*
 *  we do not have access to crypt.h on windows... 
 *   but since we link with a static version of the 
 *   library, we do have access to the crypt() function.
 */
#ifdef HAVE_LIBCRYPT
#  define HAVE_CRYPT_H

char *crypt (char *, char *);

#endif

/*
 *   These two macros are missing in winsock2.h
 */

# define timeradd(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                          \
    if ((result)->tv_usec >= 1000000)                                         \
      {                                                                       \
        ++(result)->tv_sec;                                                   \
        (result)->tv_usec -= 1000000;                                         \
      }                                                                       \
  } while (0)

# define timersub(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)

/*
 *  offcourse, identical names would be too much trouble.
 */

#define srandom(x) srand(x)
#define random	rand

/*
 *  configure script does not detect this correctly.
 */
#define HAVE_INET_NTOA

/*
 *   inet_aton wrapper around inet_addr. "good enough"
 */

static inline int inet_aton(const char *cp, struct in_addr *inp) {
  inp->s_addr = inet_addr (cp);
  if ((inp->s_addr == INADDR_NONE)&&(strcmp (cp, "255.255.255.255")))
    return 0;

  return 1;
}

/*
 * doesn't exist in windows.h
 */

static inline char *strsep (char **stringp, const char *delim) {
  char *c, *ret;
  const char *d;
  
  ret = *stringp;
  if (!ret)
    return ret;

  for (c = *stringp; *c; c++) {
    for (d = delim; *d; d++) {
      if (*c == *d) {
        *c = '\0';
        *stringp = ++c;
        return ret;
      }
    }
  }
  *stringp = NULL;
  return ret;
}

#endif
