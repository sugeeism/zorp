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
 *
 ***************************************************************************/

#include <zorp/attach.h>
#include <zorp/connect.h>
#include <zorp/dgram.h>
#include <zorp/log.h>
#include <zorp/streamfd.h>
#include <zorp/proxy.h>
#include <zorp/proxygroup.h>

#include <string.h>

/*
 * Attach - establish outgoing connection
 *
 */

struct _ZAttach
{
  gchar session_id[MAX_SESSION_ID];
  guint proto;
  ZProxy *proxy;
  ZSockAddr *bind_addr;
  ZSockAddr *local;
  ZSockAddr *remote;
  ZAttachParams params;
  ZConnector *connector;
  ZConnection *conn;
  gboolean connect_finished;
  ZAttachCallbackFunc callback;
  gpointer user_data;
  GDestroyNotify destroy_data;
};

/**
 * z_attach_callback:
 * @param self this
 * @param conn The connection to add
 *
 * Internal callback function, called when a connection is established.
 * Called from: z_attach_tcp_callback (tcp) or z_attach_start (udp).
 */
static void
z_attach_callback(ZStream *fdstream, GError *err G_GNUC_UNUSED, gpointer user_data)
{
  ZAttach *self = (ZAttach *) user_data;
  gchar buf[256];
  ZConnection *conn;

  z_session_enter(self->session_id);

  if (fdstream != NULL)
    {
      gint fd = z_stream_get_fd(fdstream);

      conn = z_connection_new();
      if (z_getsockname(fd, &conn->local, 0) != G_IO_STATUS_NORMAL ||
          z_getpeername(fd, &conn->remote, 0) != G_IO_STATUS_NORMAL)
        {
          z_connection_destroy(conn, FALSE);
          z_stream_close(fdstream, NULL);
          z_stream_unref(fdstream);
          conn = NULL;
          goto exit;
        }
      conn->protocol = self->proto;
      conn->stream = fdstream;
      conn->dest = z_sockaddr_ref(conn->remote);
    }
  else
    {
      conn = NULL;
    }

  /*LOG
    This message reports that the connection was successfully established.
  */
  z_log(self->session_id, CORE_DEBUG, 6, "Established connection; %s", z_connection_format(conn, buf, sizeof(buf)));
 exit:
  if (self->callback)
    {
      self->callback(conn, self->user_data);
    }
  else
    {
      self->conn = conn;
      self->connect_finished = TRUE;
    }

  z_session_leave(self->session_id);
}

/**
 * z_attach_start:
 * @param self this
 *
 * Initiate establishing a connection
 *
 * @return TRUE on success
 */
static gboolean
z_attach_setup_connector(ZAttach *self)
{
  z_session_enter(self->session_id);

  self->conn = NULL;
  if (self->proto == ZD_PROTO_TCP)
    {
      self->connector = z_stream_connector_new(self->session_id, self->bind_addr, self->remote, (self->params.loose ? ZSF_LOOSE_BIND : 0) | (self->params.random ? ZSF_RANDOM_BIND : 0) | ZSF_MARK_TPROXY, z_attach_callback, self, NULL);
    }
  else  if (self->proto == ZD_PROTO_UDP)
    {
      self->connector = z_dgram_connector_new(self->session_id, self->bind_addr, self->remote, (self->params.loose ? ZSF_LOOSE_BIND : 0) | (self->params.random ? ZSF_RANDOM_BIND : 0) | ZSF_MARK_TPROXY, z_attach_callback, self, NULL);
    }

  if (self->connector)
    {
      z_connector_set_timeout(self->connector, self->params.timeout < 0 ? -1 : (self->params.timeout + 999) / 1000);
      z_connector_set_tos(self->connector, self->params.tos);
      z_connector_set_mark(self->connector, self->params.server_socket_mark);
    }

  z_session_leave(self->session_id);
  return self->connector != NULL;
}

/**
 * z_attach_start:
 * @param self this
 *
 * Initiate establishing a connection
 *
 * @return TRUE on success
 */
gboolean
z_attach_start(ZAttach *self, ZPoll *poll, ZSockAddr **local)
{
  gboolean res = FALSE;
  ZProxyGroup *proxy_group;
  GMainContext *context;

  z_session_enter(self->session_id);

  if (z_attach_setup_connector(self))
    {
      if (poll)
        {
          context = z_poll_get_context(poll);
        }
      else if (self->proxy)
        {
          proxy_group = z_proxy_get_group(self->proxy);
          context = z_proxy_group_get_context(proxy_group);
        }
      else
        {
          context = NULL;
        }
      res = z_connector_start_in_context(self->connector, context, &self->local);
      if (res && local)
        *local = z_sockaddr_ref(self->local);
    }
  z_session_leave(self->session_id);
  return res;
}

gboolean
z_attach_start_block(ZAttach *self, ZConnection **conn)
{
  ZProxyGroup *proxy_group;
  gboolean res = FALSE;

  g_assert(self->callback == NULL);
  g_assert(self->connector == NULL);

  *conn = NULL;

  if (self->proxy && self->proxy->flags & ZPF_NONBLOCKING)
    {
      if (z_attach_start(self, NULL, NULL))
        {
          proxy_group = z_proxy_get_group(self->proxy);
          while (!self->connect_finished && z_proxy_group_iteration(proxy_group))
            {
              ;
            }
          *conn = self->conn;
          res = TRUE;
        }
    }
  else
    {
      if (z_attach_setup_connector(self))
        {
          ZStream *stream;

          if (z_connector_start_block(self->connector, &self->local, &stream))
            {
              z_attach_callback(stream, NULL, self);
              *conn = self->conn;
              res = TRUE;
            }
        }
    }
  return res;
}

void
z_attach_cancel(ZAttach *self)
{
  if (self->connector)
    z_connector_cancel(self->connector);
}

/**
 * z_attach_new:
 * @param proxy The proxy instance of the session
 * @param bind_addr The address to bind to
 * @param remote The address to connect to
 * @param params The optional parameters for the connection
 * @param callback Callback function to call when the connection is established
 * @param notify Callback to call when the structure is destroyed
 *
 * Allocates and sets up a new instance of ZAttach.
 * (For the connection parameters see ZAttachTCPParams and ZAttachUDPParams.)
 *
 * @return the new instance
 */
ZAttach *
z_attach_new(ZProxy *proxy,
             guint proto, ZSockAddr *bind_addr, ZSockAddr *remote,
             ZAttachParams *params,
             ZAttachCallbackFunc callback, gpointer user_data, GDestroyNotify destroy_data)
{
  ZAttach *self = g_new0(ZAttach, 1);
  gchar *session_id;

  session_id = proxy ? proxy->session_id : NULL;

  z_session_enter(session_id);
  g_strlcpy(self->session_id, session_id, sizeof(self->session_id));
  if (proxy)
    self->proxy = z_proxy_ref(proxy);
  else
    self->proxy = NULL;
  self->proto = proto;
  self->bind_addr = z_sockaddr_ref(bind_addr);
  self->remote = z_sockaddr_ref(remote);
  self->callback = callback;
  self->user_data = user_data;
  self->destroy_data = destroy_data;
  memcpy(&self->params, params, sizeof(self->params));
  z_session_leave(self->session_id);
  return self;
}

/**
 * z_attach_free:
 * @param self this
 *
 * Free a ZAttach instance,
 *
 * @return the instance
 */
void
z_attach_free(ZAttach *self)
{
  if (self)
    {
      if (self->user_data && self->destroy_data)
        {
          self->destroy_data(self->user_data);
          self->user_data = NULL;
        }
      if (self->proxy)
        z_proxy_unref(self->proxy);
      z_connector_unref(self->connector);
      z_sockaddr_unref(self->bind_addr);
      z_sockaddr_unref(self->local);
      z_sockaddr_unref(self->remote);
      g_free(self);
    }
}
