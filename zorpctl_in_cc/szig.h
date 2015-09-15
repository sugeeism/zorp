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

#ifndef ZORPCTL_SZIG_H_INCLUDED
#define ZORPCTL_SZIG_H_INCLUDED

#include "zorpctl.h"

#include <sys/types.h>

typedef struct _ZSzigContext
{
  int fd;
} ZSzigContext;

int z_szig_get_value(ZSzigContext *ctx, const char *key, char *result, size_t result_len);
int z_szig_get_sibling(ZSzigContext *ctx, const char *key, char *result, size_t result_len);
int z_szig_get_child(ZSzigContext *ctx, const char *key, char *result, size_t result_len);
int z_szig_logging(ZSzigContext *ctx, const char *subcmd, const char *param, char *result, size_t result_len);
int z_szig_reload(ZSzigContext *ctx, const char *subcmd, char *result, size_t result_len);
int z_szig_stop_session(ZSzigContext *ctx, const char *instance, char *result, size_t result_len);
int z_szig_authorize(ZSzigContext *ctx, const char *instance, int accept, const char *description, char *result, size_t result_len);
int z_szig_coredump(ZSzigContext *ctx);
int z_szig_deadlockcheck(ZSzigContext *ctx, const char *subcmd, char *result, size_t result_len);

ZSzigContext *z_szig_context_new(const char *instance_name);
void z_szig_context_destroy(ZSzigContext *ctx);

#endif
