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

#ifndef ZORP_MODULES_FTP_FTPOLICY_H
#define ZORP_MODULES_FTP_FTPOLICY_H

struct _FtpProxy;

typedef struct _FtpCommandDescriptor
{
  unsigned int flags;
  char *event;
} FtpCommandDescriptor;

typedef struct _FtpAnswerDescriptor
{
  unsigned int flags;
  char *event;
} FTPAnswerDescriptor;

gboolean ftp_policy_bounce_check(struct _FtpProxy *self,
                                    guint  side,
                                ZSockAddr *remote,
                                 gboolean  connect);
gboolean ftp_policy_parse_authinfo(struct _FtpProxy *self,
                                   const gchar *cmd,
                                   GString *param);
GHashTable *ftp_policy_command_hash_create(void);
gboolean ftp_policy_command_hash_search(struct _FtpProxy *self, gchar *command);
guint ftp_policy_command_hash_do(struct _FtpProxy *self);

ZDimHashTable *ftp_policy_answer_hash_create(void);
guint ftp_policy_answer_hash_do(struct _FtpProxy *self);

guint ftp_policy_feature_hash_search(struct _FtpProxy *self, const gchar *feature);
void ftp_policy_feature_hash_handle_insert(struct _FtpProxy *self, GHashTable *features);

#endif
