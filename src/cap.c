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

#include "cap.h"
#include "gettext.h"

/* IMPORTANT add new capabilitie names BEFORE the CAP_DEFAULT name
	otherwise printcapabilities will not work correctly */

/* *INDENT-OFF* */
flag_t Capabilities[CAP_CUSTOM_MAX + 1] = {
	{"default",	CAP_DEFAULT,	_("Default capabilities: chat, pmop, dl and search.")},
	{"reg",		CAP_REG,	_("Default REG capabilities: chat, search, pm, dl.")},
	{"vip",		CAP_VIP,	_("Default VIP capabilities: chat, search, pm, dl, share.")},
	{"kvip",	CAP_KVIP,	_("Default KVIP capabilities: chat, search, pm, dl, share, kick.")},
	{"op",		CAP_OP,		_("Default OP capabilities: chat, search, pm, dl, share, key, kick, ban.")},
	{"cheef",	CAP_CHEEF,	_("Default CHEEF capabilities: chat, search, pm, dl, share, key, kick, ban, user.")},
	{"admin",	CAP_ADMIN,	_("Default ADMIN capabilities: chat, search, pm, dl, share, key, kick, ban, user, group, inherit, config.")},

	{"owner",	CAP_OWNER,	_("Everything. All powerfull. Mostly, capable of hardbanning.")},
	{"chat", 	CAP_CHAT,	_("Allows the user to chat in main window.")},
	{"search",	CAP_SEARCH,	_("Allows user to search the hub for files.")},
	{"pmop",	CAP_PMOP,	_("Allows the user to send private messages to OPs only.")},
	{"pm", 		CAP_PM,		_("Allows the user to send private messages to anyone.")},
	{"dl", 		CAP_DL,		_("Allows user to download files.")},
	{"share",	CAP_SHARE,	_("Allows users to circumvent the share requirements.")},
	{"key", 	CAP_KEY,	_("Awards the user the much desired \"key\".")},
	{"kick",	CAP_KICK,	_("Allows the user to kick other users.")},
	{"ban", 	CAP_BAN,	_("Allows the user to ban other users.")},
	{"config", 	CAP_CONFIG,	_("Allows the user to edit the configuratoin of the hub.")},
	{"say", 	CAP_SAY,	_("Allows the user to use the \"say\" command.")},
	{"user", 	CAP_USER,	_("Allows the user to add new users.")},
	{"group", 	CAP_GROUP,	_("Allows the user to add new groups.")},
	{"inherit", 	CAP_INHERIT,	_("Allows the user to awards rights he posseses to users or groups.")},
	{"hardban", 	CAP_BANHARD,	_("Allows the user to hardban IPs. A hardban is a bit like firewalling the IP.")},
	{"tag",		CAP_TAG,	_("This users does not need a tag to get in the hub.")},
	{"sharehide",	CAP_SHAREHIDE,	_("This hides the share of the user for all excepts ops.")},
	{"shareblock",	CAP_SHAREBLOCK,	_("This blocks everyone from downloading from this user. Only works for active users.")},
	{"spam",	CAP_SPAM,	_("Users with this right can post messages as large as they want.")},
	{"nosrchlimit", CAP_NOSRCHLIMIT,_("Users with this right are not subject to search limitations.")},
	{"sourceverify",CAP_SOURCEVERIFY,_("Users with this right are only allowed into the hub if their source IP is listed for their nick in the userrestict list.")},
	{"redirect",    CAP_REDIRECT,    _("Users with this right are allowed to redirect users.")},
	{"locallan",    CAP_LOCALLAN,    _("Users with this right are allowed to use locallan ips (and avoid ctm and asearch checks).")},
	{"hidden",      CAP_HIDDEN,	 _("Users with this right do not show up in the userlist.")},
	{0, 0, 0},
};

unsigned long long next_right = (1LL << CAP_CUSTOM_FIRST);
unsigned long long used_rights = ~CAP_CUSTOM_MASK;

unsigned long long find_right () {
	unsigned long long right;
	
	if (next_right & CAP_CUSTOM_MASK) {
		right = next_right;
		next_right = next_right << 1;
		return right;
	};
	
	right = (1LL << CAP_CUSTOM_FIRST);
	while (right & used_rights) 
		right = right << 1;
	
	if (right & CAP_CUSTOM_MASK)
		return right;

	return 0;
}

flag_t *cap_custom_add (unsigned char *name, unsigned char *help) {
	unsigned int i;
	
	/* verify right does not exist */
	for (i = 0; (i < CAP_CUSTOM_MAX) && Capabilities[i].name; i++)
		if (!strcmp (Capabilities[i].name, name))   
			break;
	if (Capabilities[i].flag)
		return NULL;

	/* create new right if there isn't an old deleted one. */
	if (!Capabilities[i].name) {
		/* find empty spot */
		for (i = CAP_CUSTOM_OFFSET; i < CAP_CUSTOM_MAX; i++)
			if (!Capabilities[i].name) break;
		/* out of room? */
		if (i == CAP_CUSTOM_MAX)
			return NULL;
	}
	
	Capabilities[i].name = strdup(name);
	Capabilities[i].help = strdup(help);
	Capabilities[i].flag = find_right();
	used_rights |=  Capabilities[i].flag;
	i++;
	Capabilities[i].name = NULL;
	Capabilities[i].help = NULL;
	Capabilities[i].flag = 0;
	i--;
	return Capabilities + i;
};

int cap_custom_remove (unsigned char *name) {
	unsigned int i;
	
	/* find right */
	for (i = CAP_CUSTOM_OFFSET; i < CAP_CUSTOM_MAX; i++)
		if (!strcmp (Capabilities[i].name, name))
			break;
	/* not found */ 
	if (i == CAP_CUSTOM_MAX)
		return -1;

	// FIXME need to find a solution for this. i cannot know if this right is assigned already.
	//   this temp solution limits available rights but prevents collisions. also, assigned rights
	//   that are destroyed will not be saved.
	//used_rights &= ~Capabilities[i].flag;
	//free (Capabilities[i].name);
	//free (Capabilities[i].help); 
	//memmove (Capabilities + i, Capabilities+i+1, sizeof (flag_t)* (CAP_CUSTOM_MAX - i - 1));
	Capabilities[i].flag = 0;
	
	return 0;
}

int cap_save (xml_node_t *node) {
	unsigned int i;
	
	node = xml_node_add (node, "CustomRights");

	for (i = CAP_CUSTOM_OFFSET; i < CAP_CUSTOM_MAX; i++) {
		if (!Capabilities[i].flag) continue;
		node = xml_node_add (node, "Right");
			xml_node_add_value (node, "Name", XML_TYPE_STRING, Capabilities[i].name);
			xml_node_add_value (node, "Help", XML_TYPE_STRING, Capabilities[i].help);
		node = xml_parent (node);
	}
	return 0;
}

int cap_load (xml_node_t *node) {
	unsigned char *name = NULL, *help = NULL;
	
	node = xml_node_find (node, "CustomRights");
	if (!node) return 0;
	
	for (node = node->children; node; node = xml_next (node)) {
		if (!xml_child_get (node, "Name", XML_TYPE_STRING, &name))
			continue;
		if (!xml_child_get (node, "Help", XML_TYPE_STRING, &help))
			continue;
		cap_custom_add (name, help);
	}
	if (name)
		free (name);
	if (help)
		free (help);
	
	return 0;
}

/* *INDENT-ON* */
