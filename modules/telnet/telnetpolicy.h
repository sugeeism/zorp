/***************************************************************************
 *
 * Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef ZORP_MODULES_TELNET_TELNETPOLICY_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETPOLICY_H_INCLUDED

#include "telnet.h"

ZVerdict telnet_policy_option(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);
ZVerdict telnet_policy_suboption(TelnetProxy *self, ZEndpoint ep, guint8 option, guint8 subcommand, const gchar *name, const gchar* value);
gboolean telnet_policy_parse_authinfo(TelnetProxy *self, const gchar *env, GString *content);

#endif
