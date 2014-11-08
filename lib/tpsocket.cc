/***************************************************************************
 *
 * Copyright (c) 2000-2014 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/socket.h>
#include <zorp/tpsocket.h>
#include <zorp/log.h>
#include <zorp/cap.h>

#include <string.h>
#include <stdlib.h>

static gint
z_do_ll_getdestname(gint fd, struct sockaddr *sa, socklen_t *salen, guint32 sock_flags G_GNUC_UNUSED)
{
  return getsockname(fd, sa, salen);
}

#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

static gint
z_do_tp40_bind(gint fd, struct sockaddr *sa, socklen_t salen, guint32 sock_flags)
{
  gint on = 1, res;

  z_enter();
  if (sock_flags & ZSF_TRANSPARENT || sock_flags & ZSF_MARK_TPROXY)
    {
      if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)) < 0)
        setsockopt(fd, SOL_IP, IP_FREEBIND, &on, sizeof(on));
    }
  res = z_do_ll_bind(fd, sa, salen, sock_flags);
  z_return(res);
}

static gint
z_do_tp40_listen(int fd, gint backlog, guint32 sock_flags)
{
  static const guint32 val = Z_TP_LISTEN_SOCKET_MARK;
  gint res;

  z_enter();
  if (sock_flags & ZSF_TRANSPARENT)
    {
      /*
       * Adding mark to the client side socket (only) make passible to
       * distinguish the client and server side socket in IPTables since
       * they cannot be differenciate from each other by source/destination
       * address/port pair if they are forged.
       */
      if (setsockopt(fd, SOL_SOCKET, SO_MARK, &val, sizeof(val)) < 0)
        {
          z_log(NULL, CORE_DEBUG, 6, "Failed to add socket mark; mark='%x', errno='%s'", val, strerror(errno));
          /*
           * Should not return error because during the proxy tests Zorp runs
           * without CAP_NET_ADMIN, so error EPERM will be return by setsockopt.
           * z_return(-1);
           */
        }

    }

  res = z_do_ll_listen(fd, backlog, sock_flags);
  z_return(res);
}

static ZSocketFuncs z_tp40_socket_funcs =
{
  z_do_tp40_bind,
  z_do_ll_accept,
  z_do_ll_connect,
  z_do_tp40_listen,
  z_do_ll_getsockname,
  z_do_ll_getpeername,
  z_do_ll_getdestname
};

gboolean
z_tp_socket_init(void)
{
  socket_funcs = &z_tp40_socket_funcs;
  return TRUE;
}
