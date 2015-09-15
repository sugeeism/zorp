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

#ifndef ZORP_PROXY_SSL_H_INCLUDED
#define ZORP_PROXY_SSL_H_INCLUDED

#include <zorp/pyencryption.h>

#define PROXY_SSL_HS_CLIENT_SERVER 0
#define PROXY_SSL_HS_SERVER_CLIENT 1

#define PROXY_SSL_HS_POLICY ZV_POLICY
#define PROXY_SSL_HS_ACCEPT ZV_ACCEPT
#define PROXY_SSL_HS_VERIFIED 10

typedef struct _ZProxyTls {
  gboolean handshake_pending[EP_MAX];
  ZSSLSession *ssl_sessions[EP_MAX];
  gboolean force_connect_at_handshake;

  GString *tlsext_server_host_name;
  X509 *peer_cert[EP_MAX];

  EVP_PKEY *local_privkey[EP_MAX];
  GString  *local_privkey_passphrase[EP_MAX];
  ZCertificateChain *local_cert[EP_MAX];
  STACK_OF(X509_NAME) *server_peer_ca_list;
  gboolean certificate_trusted[EP_MAX];

  ZPolicyDict *tls_dict;
  ZPolicyObj *tls_struct;
} ZProxyTls;

struct _ZProxySSLHandshake;
typedef void (*ZProxySSLCallbackFunc)(struct _ZProxySSLHandshake *hs, gpointer user_data);
typedef struct _ZProxySSLHandshake {
  ZSSLSession *session;
  ZStream *stream;
  ZProxy *proxy;
  ZEndpoint side;

  /* result */
  gint ssl_err;
  gchar ssl_err_str[512];

  /* internals */
  GSource *timeout;

  ZStreamContext stream_context;
  ZProxySSLCallbackFunc completion_cb;
  gpointer completion_user_data;
  GDestroyNotify completion_user_data_notify;
} ZProxySSLHandshake;

ZProxySSLHandshake *z_proxy_ssl_handshake_new(ZProxy *proxy, ZStream *stream, ZEndpoint side);

void z_proxy_ssl_config_defaults(ZProxy *self);
void z_proxy_ssl_register_vars(ZProxy *self);
void z_proxy_ssl_free_vars(ZProxy *self);
gboolean z_proxy_ssl_perform_handshake(ZProxySSLHandshake *handshake);
gboolean z_proxy_ssl_init_stream(ZProxy *self, ZEndpoint side);
gboolean z_proxy_ssl_init_stream_nonblocking(ZProxy *self, ZEndpoint side);
gboolean z_proxy_ssl_request_handshake(ZProxy *self, ZEndpoint side, gboolean forced);
void z_proxy_ssl_clear_session(ZProxy *self, ZEndpoint side);
void z_proxy_ssl_set_force_connect_at_handshake(ZProxy *self, gboolean val);
void z_proxy_ssl_get_sni_from_client(ZProxy *self);
int z_proxy_ssl_verify_peer_cert_cb(int ok, X509_STORE_CTX *ctx);
int z_proxy_ssl_client_cert_cb(SSL *ssl, X509 **cert, EVP_PKEY **pkey);
int z_proxy_ssl_app_verify_cb(X509_STORE_CTX *ctx, void *user_data);
int z_proxy_ssl_tlsext_servername_cb(SSL *ssl, int *_ad G_GNUC_UNUSED, void *_arg G_GNUC_UNUSED);

#endif
