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

#include <zorp/zorp.h>
#include <zorp/stream.h>
#include <zorp/proxy.h>
#include <zorp/policy.h>
#include <zorp/thread.h>
#include <zorp/zpython.h>
#include <zorp/log.h>
#include <zorp/pysockaddr.h>

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "ftp.h"
#include "ftpolicy.h"

gboolean
ftp_policy_bounce_check(FtpProxy *self, guint  side, ZSockAddr *remote, gboolean  connect)
{
  PyObject *zsock;
  gboolean called;
  ZPolicyObj *res;
  gboolean ret;

  z_proxy_enter(self);
  z_policy_lock(self->super.thread);
  zsock = z_policy_sockaddr_new(remote);
  res = z_policy_call(self->super.handler, "bounceCheck", z_policy_var_build("(Oii)", zsock, side, connect), &called, self->super.session_id);
  if (!called)
    {
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, TRUE);
    }

  if ((res == NULL) || !z_policy_var_parse(res, "i", &ret))
    ret = FALSE;

  if (!ret)
    z_proxy_report_policy_abort(&(self->super));

  z_policy_var_unref(res);
  z_policy_var_unref(zsock);
  z_policy_unlock(self->super.thread);
  z_proxy_return(self, ret);
}

gboolean
ftp_policy_parse_authinfo(FtpProxy *self, const gchar *cmd, GString *param)
{
  gboolean called = FALSE;
  PyObject *result = NULL;
  PyObject *args = NULL;
  gboolean ret;

  z_proxy_enter(self);

  z_policy_lock(self->super.thread);

  args = z_policy_var_build("ss", cmd, param->str);
  result = z_policy_call(self->super.handler, "parseInbandAuth", args, &called, self->super.session_id);

  if (!called)
    {
      z_proxy_report_policy_abort(&(self->super));
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, FALSE);
    }

  if (result == NULL || !z_policy_var_parse(result, "i", &ret))
    ret = FALSE;

  if (result)
    z_policy_var_unref(result);

  if (!ret)
    z_proxy_report_policy_abort(&(self->super));

  z_policy_unlock(self->super.thread);

  z_proxy_return(self, ret);
}

GHashTable *
ftp_policy_command_hash_create(void)
{
  GHashTable *tmp;

  tmp = g_hash_table_new(g_str_hash, g_str_equal);

  return tmp;
}

gboolean
ftp_policy_command_hash_search(FtpProxy *self,gchar *command)
{
  FtpCommandDescriptor *tmp;

  tmp = static_cast<FtpCommandDescriptor *>(g_hash_table_lookup(self->policy_command_hash, command));
  return tmp != NULL;
}

gboolean
ftp_hash_get_type(ZPolicyObj *tuple, guint *filter_type)
{
  ZPolicyObj *tmp;

  if (!z_policy_seq_check(tuple))
    {
      if (z_policy_var_parse(tuple, "i", filter_type))
        return TRUE;
      /* not a sequence */
      return FALSE;
    }

  tmp = z_policy_seq_getitem(tuple, 0);
  if (!z_policy_var_parse(tmp, "i", filter_type))
    {
      /* policy syntax error */
      z_policy_var_unref(tmp);
      return FALSE;
    }
  z_policy_var_unref(tmp);
  return TRUE;
}

guint
ftp_policy_command_hash_do(FtpProxy *self)
{
  guint ret;
  ZPolicyObj *res;
  ZPolicyObj *tmp;
  ZPolicyObj *command_where;
  unsigned int command_do;
  gchar work[10];
  gchar *msg;
  int i;

  z_proxy_enter(self);
  tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->policy_command_hash, self->request_cmd->str));
  if (!tmp)
    {
      z_proxy_log(self, FTP_POLICY, 6, "Policy does not contain this request, trying the default; request='%s'", self->request_cmd->str);
      tmp = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->policy_command_hash, "*"));
    }
  if (!tmp)
    {
      /*LOG
        This message indicates that the policy does not contain any setting for the given
        request and Zorp rejects the request. Check the 'request' attribute.
       */
      z_proxy_log(self, FTP_POLICY, 5, "Policy does not contain this request, using hard-coded default; request='%s'", self->request_cmd->str);
      z_proxy_return(self, FTP_REQ_REJECT);
    }

  z_policy_lock(self->super.thread);
  if (!ftp_hash_get_type(tmp,&command_do))
    {
      /*LOG
        This message indicates that the policy type is invalid for the given request and Zorp
        rejects the request. Check the 'request' attribute.
       */
      z_proxy_log(self, FTP_POLICY, 1, "Policy type invalid; req='%s", self->request_cmd->str);
      z_proxy_report_invalid_policy(&(self->super));
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_policy_unlock(self->super.thread);

  switch(command_do)
    {
    case FTP_REQ_ACCEPT:
      ret = FTP_REQ_ACCEPT;
      break;

    case FTP_REQ_ABORT:
      z_policy_lock(self->super.thread);
      z_proxy_report_policy_abort(&(self->super));
      z_policy_unlock(self->super.thread);
      ret = FTP_REQ_ABORT;
      break;

    case FTP_REQ_REJECT:
      z_policy_lock(self->super.thread);
      if (z_policy_var_parse(tmp, "(is)", &command_do, &msg))
        {
          for (i = 0; i < 3; i++)
            work[i]=msg[i];

          work[i]=0;
          g_string_assign(self->answer_cmd, work);
          g_string_assign(self->answer_param, &msg[i+1]);
        }
      ret = command_do;
      z_policy_unlock(self->super.thread);
      break;

    case FTP_REQ_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(tmp,"(iO)",&command_do,&command_where))
        {
          /*LOG
            This message indicates that the policy for the given request is invalid
            and Zorp rejects the request. Check the 'request' attribute. It is likely that the
            parameter for the FTP_REQ_POLICY is invalid.
           */
          z_proxy_log(self, FTP_POLICY, 1, "Cannot parse policy line; req='%s'", self->request_cmd->str);
          z_proxy_report_invalid_policy(&(self->super));
          ret = FTP_REQ_ABORT;
        }
      else
        {
          g_string_assign(self->answer_cmd, "500");
          g_string_assign(self->answer_param, "Error parsing command");
          res = z_policy_call_object(command_where, z_policy_var_build("(s)",self->request_cmd->str), self->super.session_id);
          if (res == NULL)
            {
              /*LOG
                This message indicates that the callback for the given request policy is invalid
                and Zorp rejects the request. Check the 'request' attribute. It is likely that the
                parameter for the FTP_REQ_POLICY is invalid.
               */
              z_proxy_log(self, FTP_POLICY, 1, "Error in policy calling; req='%s'", self->request_cmd->str);
              z_proxy_report_policy_abort(&(self->super));
              ret = FTP_REQ_ABORT;
            }
          else if (!z_policy_var_parse(res,"i",&ret))
            {
              /*LOG
                This message indicates that the returned value of the callback for the given request policy
                is invalid and Zorp rejects the request. Check the callback function.
               */
              z_proxy_log(self, FTP_POLICY, 1, "Can't parsing return code; command='%s'", self->request_cmd->str);
              z_proxy_report_policy_abort(&(self->super));
              ret = FTP_REQ_ABORT;
            }
          else
            {
              switch(ret)
                {
                case FTP_REQ_ACCEPT:
                case FTP_REQ_ABORT:
                case FTP_REQ_REJECT:
                  break;

                case ZV_UNSPEC:
                case ZV_DROP:
                  ret = FTP_REQ_REJECT;
                  break;

                default:
                  break;
                }
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    default:
      ret = FTP_REQ_ABORT;
      break;
    }
  z_proxy_return(self, ret);
}

ZDimHashTable *
ftp_policy_answer_hash_create(void)
{
  ZDimHashTable *tmp;

  tmp = z_dim_hash_table_new(2, 2, DIMHASH_WILDCARD, DIMHASH_CONSUME);
  return tmp;
}

guint
ftp_policy_answer_hash_do(FtpProxy *self)
{
  guint ret;
  ZPolicyObj *res;
  ZPolicyObj *tmp;
  ZPolicyObj *answer_where;
  unsigned int answer_do;
  gchar key1[5];
  gchar key2[5];
  gchar *key[2];
  gchar *msg;
  int i;
  gchar work[10];

  z_proxy_enter(self);
  if (self->request_cmd->len > 0)
    g_snprintf(key1, sizeof(key1), "%s", self->request_cmd->str);
  else
    g_snprintf(key1, sizeof(key1), "Null");

  g_snprintf(key2, sizeof(key2), "%s", self->answer_cmd->str);
  key[0] = key1;
  key[1] = key2;
  tmp = static_cast<ZPolicyObj *>(z_dim_hash_table_search(self->policy_answer_hash, 2, key));
  if (!tmp)
    {
      /*LOG
        This message indicates that the policy does not contain any setting for the given
        response and Zorp rejects the response. Check the 'response' attribute.
       */
      z_proxy_log(self, FTP_POLICY, 5, "Policy does not contain this response, using hard-coded default; request='%s', response='%s", self->request_cmd->str, self->answer_cmd->str);
      z_proxy_return(self, FTP_RSP_REJECT);
    }

  z_policy_lock(self->super.thread);
  if (!ftp_hash_get_type(tmp, &answer_do))
    {
      /*LOG
        This message indicates that the policy type is invalid for the given response and Zorp
        rejects the request. Check the 'request' attribute.
       */
      z_proxy_log(self, FTP_POLICY, 1, "Answer type invalid; req='%s', rsp='%s'", self->request_cmd->str, self->answer_cmd->str);
      z_proxy_report_invalid_policy(&(self->super));
      z_policy_unlock(self->super.thread);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_policy_unlock(self->super.thread);

  switch(answer_do)
    {
    case FTP_RSP_REJECT:
      ret = FTP_RSP_REJECT;
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(tmp, "(is)", &answer_do, &msg))
        {
          g_string_assign(self->answer_cmd, "500");
          g_string_assign(self->answer_param, "Error parsing answer");
        }
      else
        {
          for(i = 0; i < 3; i++)
            work[i]=msg[i];
          work[i]=0;
          g_string_assign(self->answer_cmd, work);
          g_string_assign(self->answer_param, &msg[i+1]);
        }
      z_policy_unlock(self->super.thread);
      break;

    case FTP_RSP_ACCEPT:
      ret = FTP_RSP_ACCEPT;
      break;

    case FTP_RSP_ABORT:
      ret = FTP_RSP_ABORT;
      z_policy_lock(self->super.thread);
      z_proxy_report_policy_abort(&(self->super));
      if (!z_policy_var_parse(tmp, "(is)", &answer_do, &msg))
        {
          g_string_assign(self->answer_cmd, "500");
          g_string_assign(self->answer_param, "Error parsing answer");
        }
      else
        {
          for(i = 0; i < 3; i++)
            work[i]=msg[i];
          work[i]=0;
          g_string_assign(self->answer_cmd, work);
          g_string_assign(self->answer_param, &msg[i+1]);
        }
      z_policy_unlock(self->super.thread);
      break;

    case FTP_RSP_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(tmp,"(iO)", &answer_do, &answer_where))
        {
          /*LOG
            This message indicates that the policy for the given response is invalid
            and Zorp rejects the response. Check the 'response' attribute. It is likely that the
            parameter for the FTP_RSP_POLICY is invalid.
           */
          z_proxy_log(self, FTP_POLICY, 1, "Bad policy line; command='%s', answer='%s'", self->request_cmd->str, self->answer_cmd->str);
          g_string_assign(self->answer_cmd, "500");
          g_string_assign(self->answer_param, "Error parsing answer (bad policy)");
          z_proxy_report_invalid_policy(&(self->super));
          ret = FTP_RSP_ABORT;
        }
      else
        {
          res = z_policy_call_object(answer_where, z_policy_var_build("(ss)", self->request_cmd->str, self->answer_cmd->str), self->super.session_id);
          if (res == NULL)
            {
              /*LOG
                This message indicates that the callback for the given response policy is invalid
                and Zorp rejects the response. Check the 'response' attribute. It is likely that the
                parameter for the FTP_RSP_POLICY is invalid.
               */
              z_proxy_log(self, FTP_POLICY, 1, "Error in policy calling; command='%s', answer='%s'", self->request_cmd->str, self->answer_cmd->str);
              g_string_assign(self->answer_cmd, "500");
              g_string_assign(self->answer_param, "Error parsing answer (bad policy)");
              z_proxy_report_policy_abort(&(self->super));
              ret = FTP_RSP_ABORT;
            }
          else if (!z_policy_var_parse(res, "i", &ret))
            {
              /*LOG
                This message indicates that the returned value of the callback for the given response policy
                is invalid and Zorp rejects the response. Check the callback function.
               */
              z_proxy_log(self, FTP_POLICY, 1, "Return code invalid from policy function; command='%s', answer='%s'", self->request_cmd->str, self->answer_cmd->str);
              g_string_assign(self->answer_cmd, "500");
              g_string_assign(self->answer_param, "Error parsing answer (bad policy)");
              z_proxy_report_policy_abort(&(self->super));
              ret = FTP_RSP_ABORT;
            }
          else
            {
              switch(ret)
                {
                case FTP_RSP_ACCEPT:
                case FTP_RSP_REJECT:
                case FTP_RSP_ABORT:
                  break;

                case ZV_DROP:
                case ZV_UNSPEC:
                  ret = FTP_RSP_REJECT;
                  break;

                default:
                  g_string_assign(self->answer_cmd, "500");
                  g_string_assign(self->answer_param, "Error parsing answer, connection dropped.");
                  z_proxy_report_policy_abort(&(self->super));
                  ret = FTP_RSP_ABORT;
                  break;
                }
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    default:
      g_string_assign(self->answer_cmd, "500");
      g_string_assign(self->answer_param, "Error parsing answer, connection dropped.");

      z_policy_lock(self->super.thread);
      z_proxy_report_policy_abort(&(self->super));
      z_policy_unlock(self->super.thread);

      ret = FTP_RSP_ABORT;
      break;
    }
  z_proxy_return(self, ret);
}

/* only 8 char FTP command is allowed now
 * 4 is used now, but +1 byte is needed for trailing 0,
 * so it is padded to 8 byte */
typedef char t_ftp_command[8];

static void
strip_parameters_from_ftp_command(const char *name, t_ftp_command ftp_command)
{
  unsigned i = 0;

  memset(ftp_command, 0, sizeof(t_ftp_command));

  while (name && i < sizeof(t_ftp_command))
    {
      if (!g_ascii_isupper(*name))
        break;
      ftp_command[i++] = *name++;
    }
}

guint
ftp_policy_feature_hash_search(struct _FtpProxy *self, const gchar *feature)
{
  ZPolicyObj *res;
  guint verdict;
  gboolean valid;
  t_ftp_command ftp_command;

  z_proxy_enter(self);

  strip_parameters_from_ftp_command(feature, ftp_command);
  res = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->policy_features, ftp_command));
  if (!res)
    res = static_cast<ZPolicyObj *>(g_hash_table_lookup(self->policy_features, "*"));

  if (!res)
    {
      /*LOG
        This message indicates that the policy does not contain any setting for the given
        feature and Zorp drops the feature. Check the 'features' attribute.
       */
      z_proxy_log(self, FTP_POLICY, 5, "Policy does not contain this feature, dropping; feature='%s'", feature);
      z_proxy_return(self, FTP_FEATURE_DROP);
    }

  z_policy_lock(self->super.thread);
  valid = ftp_hash_get_type(res, &verdict);
  z_policy_unlock(self->super.thread);

  if (!valid)
    {
      /*LOG
        This message indicates that the policy type is invalid for the given feature and
        thus Zorp drops the feature.
       */
      z_proxy_log(self, FTP_POLICY, 1, "Policy value invalid; feature='%s'", feature);
      z_proxy_return(self, FTP_FEATURE_DROP);
    }

  z_proxy_return(self, verdict);
}

static void
ftp_policy_feature_hash_foreach_cb(gpointer _key, gpointer _value,
                                   gpointer user_data)
{
  gchar *key = (gchar *) _key;
  ZPolicyObj *verdict = (ZPolicyObj *) _value;
  GHashTable *features = (GHashTable *) user_data;
  guint verdict_parsed;

  if (ftp_hash_get_type(verdict, &verdict_parsed)
      && (verdict_parsed == FTP_FEATURE_INSERT))
    g_hash_table_insert(features, key, NULL);
}

void
ftp_policy_feature_hash_handle_insert(struct _FtpProxy *self, GHashTable *features)
{
  z_proxy_enter(self);

  z_policy_lock(self->super.thread);
  g_hash_table_foreach(self->policy_features, ftp_policy_feature_hash_foreach_cb, features);
  z_policy_unlock(self->super.thread);

  z_proxy_leave(self);
}
