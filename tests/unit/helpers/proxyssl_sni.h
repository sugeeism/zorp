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

#ifndef TESTS_UNIT_HELPERS_PROXYSSL_SNI_H_INCLUDED
#define TESTS_UNIT_HELPERS_PROXYSSL_SNI_H_INCLUDED
#include <zorp/proxy.h>

typedef struct _ProxySSL_SNI_stubs_called
{
  gboolean times_z_proxy_ssl_use_local_cert_and_key;
} ProxySSL_SNI_stubs_called;

ProxySSL_SNI_stubs_called * proxyssl_sni_get_stubs_called(void);
void proxyssl_sni_clear_times_stubs_called(void);

// Stub functions
const char *SSL_get_servername(const SSL *s, const int type);
gboolean z_proxy_ssl_use_local_cert_and_key(ZProxy *self, ZEndpoint side, SSL *ssl);

#endif /* TESTS_UNIT_HELPERS_PROXYSSL_SNI_H_INCLUDED */
