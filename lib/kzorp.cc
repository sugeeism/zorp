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

#include <zorp/zorp.h>
#include <zorp/kzorp-kernel.h>
#include <zorp/log.h>

#include <netinet/ip.h>

gboolean
z_kzorp_get_lookup_result(guint8 family, gint fd, struct z_kzorp_lookup_result *result)
{
  socklen_t size = sizeof(*result);
  int level;

  z_enter();

  switch (family)
    {
    case PF_INET:
      level = SOL_IP;
      break;
    case PF_INET6:
      level = SOL_IPV6;
      break;
    default:
      g_assert_not_reached();
      break;
    }

  if (getsockopt(fd, level, SO_KZORP_RESULT, result, &size) < 0)
    {
      z_log(NULL, CORE_ERROR, 3, "Error querying KZorp lookup result; fd='%d', error='%s'", fd, g_strerror(errno));
      z_return(FALSE);
    }

  z_return(TRUE);
}
