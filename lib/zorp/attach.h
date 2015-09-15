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

#ifndef ZORP_ATTACH_H_INCLUDED
#define ZORP_ATTACH_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/connection.h>
#include <zorp/proxy.h>

typedef struct _ZAttachTCPParams
{
} ZAttachTCPParams;

typedef struct _ZAttachUDPParams
{
} ZAttachUDPParams;

typedef struct _ZAttachParams
{
  gint timeout;
  gboolean loose;       /**< choose port in the same group if the port can't be bound */
  gboolean random;      /**< choose port in the same group randomly (securely). if TRUE, loose should be TRUE too. */
  gint tos;
  union
  {
    ZAttachTCPParams tcp;
    ZAttachUDPParams udp;
  };
  guint32 server_socket_mark;
} ZAttachParams;

typedef struct _ZAttach ZAttach;

typedef void (*ZAttachCallbackFunc)(ZConnection *, gpointer user_data);

gboolean z_attach_start(ZAttach *self, ZPoll *poll, ZSockAddr **local);
gboolean z_attach_start_block(ZAttach *self, ZConnection **conn);
void z_attach_cancel(ZAttach *self);

ZAttach *z_attach_new(ZProxy *proxy, guint proto, ZSockAddr *local, ZSockAddr *remote, ZAttachParams *params, ZAttachCallbackFunc callback, gpointer user_data, GDestroyNotify destroy_data);
void z_attach_free(ZAttach *self);

#endif
