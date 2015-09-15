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

#ifndef ZORP_DIMHASH_H_INCLUDED
#define ZORP_DIMHASH_H_INCLUDED

#include <zorp/zorp.h>

#define DIMHASH_WILDCARD 0x001
#define DIMHASH_CONSUME  0x002

#define DIMHASH_MAX_KEYNUM    5
#define DIMHASH_MAX_KEYSIZE 100

typedef struct _ZDimHashTable
{
  GHashTable *hash;
  guint keynum;
  guint minkeynum;
  guint *flags;
} ZDimHashTable;

typedef gboolean (*ZDimHashFreeFunc)(void *value);

void z_dim_hash_key_free(int num, gchar **key);

ZDimHashTable *z_dim_hash_table_new(guint minnum, guint num, ...);
void z_dim_hash_table_free(ZDimHashTable *self, ZDimHashFreeFunc func);

gpointer z_dim_hash_table_lookup(ZDimHashTable  *self,
                                         guint   num,
                                         gchar **keys);
void     z_dim_hash_table_delete(ZDimHashTable  *self,
                                         guint   num,
                                         gchar **keys,
                              ZDimHashFreeFunc   func);
void     z_dim_hash_table_insert(ZDimHashTable  *self,
                                      gpointer   value,
                                         guint   num,
                                         gchar **keys);

gpointer z_dim_hash_table_search(ZDimHashTable  *self,
                                         guint   num,
                                         gchar **keys);

#endif
