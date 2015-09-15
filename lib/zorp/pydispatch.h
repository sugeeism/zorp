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

#ifndef ZORP_PYDISPATCH_H_INCLUDED
#define ZORP_PYDISPATCH_H_INCLUDED

#include <zorp/zpython.h>
#include <zorp/pystruct.h>
#include <zorp/dispatch.h>

typedef struct _ZPolicyDispatchBind ZPolicyDispatchBind;

ZDispatchBind *
z_policy_dispatch_bind_get_db(ZPolicyObj *self);

static inline gboolean
z_policy_dispatch_bind_check(ZPolicyObj *self)
{
  return z_policy_struct_check(self, Z_PST_DB_SOCKADDR) || z_policy_struct_check(self, Z_PST_DB_IFACE) || z_policy_struct_check(self, Z_PST_DB_IFACE_GROUP);
}

void z_policy_dispatch_module_init(void);

#endif
