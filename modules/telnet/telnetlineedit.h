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

#ifndef ZORP_MODULES_TELNET_TELNETLINEEDIT_H_INCLUDED
#define ZORP_MODULES_TELNET_TELNETLINEEDIT_H_INCLUDED

#include <zorp/packetbuf.h>

typedef enum _TelnetLineEditChars
  {
    LINEEDIT_BACKSPACE = 0x7f,
    LINEEDIT_LINEDEL = 0x15,
  } TelnetLineEditChars;

typedef struct _TelnetLineEdit
{
  ZPktBuf *data_buffer;
  gboolean do_echo;
  gboolean eol;
  gboolean echo_newline;

} TelnetLineEdit;

void telnet_lineedit_init(TelnetLineEdit *self);
void telnet_lineedit_destroy(TelnetLineEdit *self);

ZPktBuf *telnet_lineedit_process_data(TelnetLineEdit *self, ZPktBuf *data);
void telnet_lineedit_clear(TelnetLineEdit *self);

ZPktBuf *telnet_lineedit_compose_delete_n_chars(gsize n);
#endif
