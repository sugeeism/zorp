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

#ifndef ZORP_DGRAM_H_INCLUDED
#define ZORP_DGRAM_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/zobject.h>
#include <zorp/listen.h>
#include <zorp/connect.h>

extern ZClass ZDGramListener__class;

gboolean z_dgram_init(void);

ZListener *
z_dgram_listener_new(const gchar *session_id,
                     ZSockAddr *local,
                     guint32 sock_flags,
                     gint rcvbuf,
                     ZAcceptFunc callback,
                     gpointer user_data);

extern ZClass ZDGramConnector__class;

static inline ZConnector *
z_dgram_connector_new(const gchar *session_id,
                      ZSockAddr *local,
                      ZSockAddr *remote,
                      guint32 sock_flags,
                      ZConnectFunc callback,
                      gpointer user_data,
                      GDestroyNotify destroy_data)
{
  return z_connector_new(Z_CLASS(ZDGramConnector), session_id, SOCK_DGRAM, local, remote, sock_flags, callback, user_data, destroy_data);
}

#endif
