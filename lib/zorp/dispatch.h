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

#ifndef ZORP_DISPATCH_H_INCLUDED
#define ZORP_DISPATCH_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/stream.h>
#include <zorp/sockaddr.h>
#include <zorp/connection.h>

class ZDispatchEntry;
class ZDispatchBind;

/* dispatching priorities */

enum
{
  ZD_PRI_LISTEN=100,    /* used by listeners and receivers */
  ZD_PRI_NORMAL=0,      /* used by proxies supporting several subsessions for fastpath*/
  ZD_PRI_RELATED=-100,  /* used by proxies needing related connections, e.g. FTP data stream */
};

enum ZDispatchBindType
{
  ZD_BIND_NONE,
  ZD_BIND_SOCKADDR,
  ZD_BIND_IFACE,
  ZD_BIND_IFACE_GROUP,
};

typedef struct _ZDispatchCommonParams
{
  gboolean threaded;
  gboolean mark_tproxy;
  gboolean transparent;
} ZDispatchCommonParams;

typedef struct _ZDispatchTCPParams
{
  gboolean accept_one; /* prohibits other dispatch_registers */
  gint backlog;        /* listen backlog, the first dispatch registration counts */
} ZDispatchTCPParams;

typedef struct _ZDispatchUDPParams
{
  gint rcvbuf;
} ZDispatchUDPParams;

typedef struct _ZDispatchParams
{
  ZDispatchCommonParams common;
  union
  {
    ZDispatchTCPParams tcp;
    ZDispatchUDPParams udp;
  };
} ZDispatchParams;

typedef gboolean (*ZDispatchCallbackFunc)(ZConnection *conn, gpointer user_data);

/* ZDispatchBind */

/* The dispatch_table hashtable contains ZDispatchEntry structures keyed
 * with instances of this type */
class ZDispatchBind
{
public:
  ZRefCount ref_cnt;
  gushort protocol;
  gushort type;
  union
  {
    struct
    {
      ZSockAddr *addr;
    } sa;
    struct
    {
      gchar iface[16];
      gint family;
      struct in_addr ip4;
      gushort port;
    } iface;
    struct
    {
      guint32 group;
      gint family;
      gushort port;
    } iface_group;
  };
};

ZDispatchBind *z_dispatch_bind_new_sa(guint protocol, ZSockAddr *addr);
ZDispatchBind *z_dispatch_bind_new_iface(guint protocol, const gchar *iface, gint family, const gchar *ip, guint port);
ZDispatchBind *z_dispatch_bind_new_iface_group(guint protocol, guint32 group, gint family, guint port);

gchar *z_dispatch_bind_format(ZDispatchBind *self, gchar *buf, gsize buflen);
ZDispatchBind *z_dispatch_bind_ref(ZDispatchBind *self);
void z_dispatch_bind_unref(ZDispatchBind *self);

/* Dispatch main entry points */

ZDispatchEntry *
z_dispatch_register(gchar *session_id,
                        ZDispatchBind *key,
		        ZSockAddr **bound_addr,
                        gint prio,
                        ZDispatchParams *params,
                        ZDispatchCallbackFunc cb, gpointer user_data, GDestroyNotify data_destroy);

void z_dispatch_unregister(ZDispatchEntry *de);

void z_dispatch_init(void);
void z_dispatch_destroy(void);

#endif
