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
 ***************************************************************************/

#ifndef ZORP_PROXY_ERRORLOADER_H_INCLUDED
#define ZORP_PROXY_ERRORLOADER_H_INCLUDED

#include <zorp/zorp.h>

enum
{
  Z_EF_ESCAPE_NONE = 0x0001,
  Z_EF_ESCAPE_HTML = 0x0002,
};

typedef gchar *(*ZErrorLoaderResolveFunc)(const gchar *variable, gpointer user_data);

typedef struct _ZErrorLoaderVarInfo
{
  const gchar *variable;
  ZErrorLoaderResolveFunc resolve;
} ZErrorLoaderVarInfo;

gchar *
z_error_loader_format_file(gchar *filepath, gchar *additional_info, guint32 flags, ZErrorLoaderVarInfo *infos, gpointer user_data);

#endif
