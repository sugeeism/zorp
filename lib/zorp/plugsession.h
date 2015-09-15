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
#ifndef ZORP_PLUGSESSION_H_INCLUDED
#define ZORP_PLUGSESSION_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/poll.h>
#include <zorp/proxystack.h>

typedef struct _ZPlugSession ZPlugSession;

typedef struct _ZPlugSessionData
{
  gint timeout;
  gboolean copy_to_server, copy_to_client;
  gboolean shutdown_soft;
  guint buffer_size;
  guint packet_stats_interval_time, packet_stats_interval_packet;

  gboolean (*packet_stats)(ZPlugSession *self,
                           guint64 client_bytes, guint64 client_pkts,
                           guint64 server_bytes, guint64 server_pkts,
                           gpointer user_data);
  void (*finish)(ZPlugSession *self, gpointer user_data);
  void (*timeout_cb) (ZPlugSession *self, gpointer user_data);
} ZPlugSessionData;

gboolean z_plug_session_start(ZPlugSession *self, ZPoll *poll);
void z_plug_session_cancel(ZPlugSession *self);
void z_plug_session_register_vars(ZPlugSession *self, ZPolicyDict *dict);

ZPlugSession *
z_plug_session_new(ZPlugSessionData *session_data,
                   ZStream *client_stream,
                   ZStream *server_stream,
                   ZStackedProxy *stacked,
                   gpointer user_data);

void z_plug_session_destroy(ZPlugSession *self);

ZPlugSession *z_plug_session_ref(ZPlugSession *self);
void z_plug_session_unref(ZPlugSession *self);

#endif
