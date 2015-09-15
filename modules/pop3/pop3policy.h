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

#ifndef ZORP_MODULES_POP3POLICY_H_INCLUDED
#define ZORP_MODULES_POP3POLICY_H_INCLUDED

#include "pop3.h"

guint pop3_policy_command_hash_search(Pop3Proxy *self,gchar *command);

gboolean ftp_hash_get_type(ZPolicyObj *tuple, guint *filter_type);

guint pop3_policy_command_hash_do(Pop3Proxy *self);

guint pop3_policy_response_hash_do(Pop3Proxy *self);

gboolean pop3_policy_stack_hash_do(Pop3Proxy *self, ZStackedProxy **stacked);

#endif
