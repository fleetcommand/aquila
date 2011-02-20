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

#include "../config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../src/cap.h"

#ifndef USE_WINDOWS
#  ifdef HAVE_CRYPT_H
#    include <crypt.h>
#  endif
#else
#  define random(x) rand(x)
#  define srandom(x) srand(x)

char *crypt (char *, char *);

#endif

int main (int argc, char **argv)
{
  unsigned char salt[3];
  FILE *fp;

  if (argc < 4) {
    printf ("%s <filename> <user> <passwd>\n", argv[0]);
    return 0;
  }

  srandom (time (NULL));
  salt[2] = 0;
  fp = fopen (argv[1], "a");
  if (!fp) {
    perror ("Error: ");
    return 0;
  }

  if (ftell (fp) == 0) {
    fprintf (fp, "T regs %lu 5\n", CAP_REG);
    fprintf (fp, "T vips %lu 4\n", CAP_VIP);
    fprintf (fp, "T ops %lu 3\n", CAP_OP);
    fprintf (fp, "T cheefs %lu 2\n", CAP_CHEEF);
    fprintf (fp, "T admins %lu 1\n", CAP_ADMIN);
    fprintf (fp, "T owner %lu 0\n", CAP_ADMIN | CAP_OWNER);
  } else
    printf ("Appending new owner %s to file %s\n", argv[2], argv[1]);

  do {
    salt[0] = ((random () % 78) + 45);
  } while ( ((salt[0] > 57)&&(salt[0] < 65))||((salt[0] > 90)&&(salt[0] < 97)) );
  do { 
    salt[1] = ((random () % 78) + 45);
  } while ( ((salt[1] > 57)&&(salt[1] < 65))||((salt[1] > 90)&&(salt[1] < 97)) );
  salt[2] = 0;

  fprintf (fp, "A %s %s %lu %lu %lu %s %lu %lu\n", argv[2], crypt (argv[3], salt), CAP_ADMIN | CAP_OWNER, 0, 0, argv[2], time(NULL), 0);

  fclose (fp);

  return 0;
}
