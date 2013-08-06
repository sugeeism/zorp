/***************************************************************************
 *
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
 * 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author: Laszlo Attila Toth <laszlo.attila.toth@balabit.com>
 *
 ***************************************************************************/

#ifndef ZORP_SESSION_IMPL_H_INCLUDED
#define ZORP_SESSION_IMPL_H_INCLUDED

#include <glib.h>
#include <semaphore.h>

#define ZORP_LICENSES_SHMEM_NAME      "/zorp-licenses"
#define ZORP_LICENSES_SEMAPHORE_NAME  "/zorp-licenses-sem"

enum
 {
    ZORP_LICENSES_INSTANCE_NAME_LENGTH = 64,
    ZORP_LICENSES_SHMEM_SIZE  = (71 * 1024),
 };

typedef struct _ZInstanceEntry
{
  pid_t     pid;
  gchar     name[ZORP_LICENSES_INSTANCE_NAME_LENGTH];
  guint32   count;
} ZInstanceEntry;

typedef struct _ZSessionShmemData
{
  guint32 instance_count;
  ZInstanceEntry entries[0];
} ZSessionShmemData;

typedef struct _ZSessionInfo
{
  guint   max_instance_count;
  double  graceful_session_limit_modifier;

  int       fd;
  sem_t    *sem;
  ZSessionShmemData *data;
  ZInstanceEntry *self_row;
} ZSessionInfo;

extern ZSessionInfo session_info;

void z_session_lock();
void z_session_unlock();

#endif /* ZORP_SESSION_IMPL_H_INCLUDED */
