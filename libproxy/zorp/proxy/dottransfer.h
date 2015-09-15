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
 ***************************************************************************/

#ifndef ZORP_DOTTRANSFER_H_INCLUDED
#define ZORP_DOTTRANSFER_H_INCLUDED

#include <zorp/proxy/transfer2.h>

enum
{
  DOT_DW_PREAMBLE = 0,
  DOT_DW_DATA     = 1,
  DOT_DW_DATA_LF  = 2,
  DOT_DW_DATA_DOT = 3,
};

typedef struct _ZDotTransfer
{
  ZTransfer2 super;
  gboolean previous_line_split;
  GString *preamble;
  guint preamble_ofs;
  guint dst_write_state;
} ZDotTransfer;

extern ZClass ZDotTransfer__class;

ZDotTransfer *
z_dot_transfer_new(ZClass *class_,
                   ZProxy *owner,
                   ZPoll *poll,
                   ZStream *client, ZStream *server,
                   gsize buffer_size,
                   glong timeout,
                   gulong flags,
                   GString *preamble);

#endif
