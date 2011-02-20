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
#include "hub.h"

#include <string.h>

#include "proto.h"
#include "config.h"
#include "nmdc_protocol.h"
#include "nmdc_local.h"

/******************************************************************************\
**                                                                            **
**                                FUNCTIONS                                   **
**                                                                            **
\******************************************************************************/

int nmdc_init ()
{
  return nmdc_proto.init ();
}

int nmdc_setup (esocket_handler_t * h)
{
  config_element_t *listenport;
  config_element_t *listenaddress;;
  config_element_t *extraports;

  nmdc_proto.setup ();

  listenaddress = config_find ("NMDC.listenaddress");

  /* setup main listen port */
  listenport = config_find ("NMDC.listenport");
  if (listenport)
    server_add_port (h, &nmdc_proto,
		     (listenaddress ? *listenaddress->val.v_ip : 0L), *listenport->val.v_uint);

  /* setup extra nmdc ports */
  extraports = config_find ("NMDC.ExtraPorts");
  if (extraports && **extraports->val.v_string) {
    unsigned long port;
    char *work, *p;

    work = strdup (*extraports->val.v_string);

    p = work;
    while (*p && (port = strtol (p, &p, 0))) {
      server_add_port (h, &nmdc_proto, (listenaddress ? *listenaddress->val.v_ip : 0L), port);
      while ((*p == ' ') || (*p == ','))
	p++;
    }

    free (work);
  }

  return 0;
}
