/***************************************************************************
 *
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
 * 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * Note that this permission is granted for only version 2 of the GPL.
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ***************************************************************************/

#ifndef ZORP_MODULES_TELNET_TELNETOPTION_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETOPTION_H_INCLUDED

#include "telnet.h"

gboolean telnet_option_do(TelnetProxy *self, const ZEndpoint ep, const guint8 option);
gboolean telnet_option_will(TelnetProxy *self, const ZEndpoint ep, const guint8 option);

gboolean telnet_option_do_in_progress(TelnetProxy *self, const ZEndpoint ep, const guint8 option);
gboolean telnet_option_will_in_progress(TelnetProxy *self, const ZEndpoint ep, const guint8 option);

void telnet_option_command_received(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);
void telnet_option_command_sent(TelnetProxy *self, ZEndpoint ep, guint8 command, guint8 option);

#endif
/*
# Local Variables:
# indent-tabs-mode: nil
# End:
*/
