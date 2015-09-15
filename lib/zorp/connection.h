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

#ifndef ZORP_CONNECTION_H_INCLUDED
#define ZORP_CONNECTION_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/stream.h>
#include <zorp/sockaddr.h>

struct ZDispatchBind;

enum
{
  ZD_PROTO_AUTO = 0,
  ZD_PROTO_TCP = 1,
  ZD_PROTO_UDP = 2,
};

typedef struct _ZConnection
{
  guint protocol;
  ZStream *stream;
  ZSockAddr *remote; /* the peer's address */
  ZSockAddr *local;  /* the explicit local address (no wildcard port spec) */
  ZSockAddr *dest;   /* the original destination of the client */
  ZDispatchBind *dispatch_bind;
} ZConnection;

ZConnection *z_connection_new(void);
gchar *z_connection_format(ZConnection *conn, gchar *buf, gint buflen);
void z_connection_destroy(ZConnection *conn, gboolean close);

#endif
