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

#include <zorp/authprovider.h>
#include <zorp/log.h>


/**
 * z_auth_provider_check_passwd:
 *
 * NOTE: this function requires the Python lock to be held.
 **/
gboolean
z_auth_provider_check_passwd(ZAuthProvider *self G_GNUC_UNUSED,
                             gchar *session_id G_GNUC_UNUSED,
                             gchar *username G_GNUC_UNUSED,
                             gchar *passwd G_GNUC_UNUSED,
                             gchar ***groups G_GNUC_UNUSED,
                             ZProxy *proxy G_GNUC_UNUSED)
{
  return FALSE;
}
