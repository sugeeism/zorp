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

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include "../http.h"

#define TEST_STR(field) \
  do 											\
    {											\
      if (ok && 									\
          ((field && memcmp(field, url. field->str, url. field->len) != 0) ||		\
           (!field && url. field->len)))    						\
        { 										\
          fail_reason = g_strdup_printf("Returned and expected value for " #field " mismatch: %s <> %s", url. field->str, field);		\
          ok = FALSE;									\
        }										\
    }											\
  while (0)

void
test_case(gint id, gchar *url_str, gboolean unicode, gboolean invalid_escape, gboolean expected_valid, gchar *scheme, gchar *user, gchar *passwd, gchar *host, guint port, gchar *file, gchar *query, gchar *fragment)
{
  HttpURL url;
  gchar *fail_reason = NULL;
  const gchar *error_reason = NULL;
  gboolean ok = TRUE, valid;

  http_init_url(&url);
  valid = http_parse_url(&url, unicode, invalid_escape, FALSE, url_str, &error_reason);

  if (ok && valid != expected_valid)
    {
      fail_reason = g_strdup_printf("Parse result different than expected: %s", !valid ? error_reason : "No error");
      ok = FALSE;
    }
  if (valid)
    {
      TEST_STR(scheme);
      TEST_STR(user);
      TEST_STR(passwd);
      TEST_STR(host);
      if (ok && port && port != url.port)
        {
          fail_reason = g_strdup("Return and expected value for port mismatch");
          ok = FALSE;
        }
      TEST_STR(file);
      TEST_STR(query);
      TEST_STR(fragment);
    }

  BOOST_CHECK_MESSAGE(ok, "test failure, id=" << id << ", url=" << url_str << ", reason=" << fail_reason);
}

struct
{
  gchar *url_str;
  gboolean invalid_escape;
  gboolean unicode;
  gboolean valid;
  gchar *scheme;
  gchar *user;
  gchar *passwd;
  gchar *host;
  guint port;
  gchar *file;
  gchar *query;
  gchar *fragment;
} test_table[] =

#define NA NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL

{
  { "http://user:pass@test.host:8080/file",    FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 8080, "/file",        NULL, NULL },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        NULL, NULL },
  { "http://user:pass@test.host",              FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/",            NULL, NULL },
  { "http://user:pass@test.host?",             FALSE, FALSE, FALSE, NA },
  { "http://user:pass@test.host#",             FALSE, FALSE, FALSE, NA },
  { "http://user:pass@test.host/file?query#fragment",
                                               FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        "query", "fragment" },
  { "http://user:pass@test.host/file#fragment?start",
                                               FALSE, FALSE, FALSE, NA },
  { "http://user:pass@test.host/file#fragment",
                                               FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        NULL, "fragment" },
  { "http://user:pass@test.host/file?query",
                                               FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        "query", NULL },
  { "http://user@test.host:8080/file",         FALSE, FALSE, TRUE, "http", "user", NULL,   "test.host", 8080, "/file",        NULL, NULL },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        NULL, NULL },
  { "http://user@test.host/file",              FALSE, FALSE, TRUE, "http", "user", NULL,   "test.host", 0,    "/file",        NULL, NULL },
  { "http://test.host:8080/file",              FALSE, FALSE, TRUE, "http", NULL,   NULL,   "test.host", 8080, "/file",        NULL, NULL },
  { "http://test.host/file",                   FALSE, FALSE, TRUE, "http", NULL,   NULL,   "test.host", 0,    "/file",        NULL, NULL },
  { "http://user:pass:test.host:54/file",      FALSE, FALSE, FALSE, NA  },
  { "http://www.korridor.hu/default.ida?NNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u0090=a",
                                               FALSE, FALSE, FALSE, NA },
  { "http://test.host/default.idaNNNN%u9090%u6858%ucbd3",
                                               FALSE, TRUE,  TRUE,  "http",  NULL,   NULL,  "test.host", 0,    "/default.ida\x4e\x4e\x4e\x4e\xe9\x82\x90\xe6\xa1\x98\xec\xaf\x93",
                                                                                                                              NULL, NULL },
  { "http://test.host/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=%5B%25GMTTIME%25%5D?",
                                               FALSE, FALSE, TRUE, "http", NULL,   NULL,   "test.host", 0,    "/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=[%GMTTIME%]",
                                                                                                                              NULL, NULL },
  { "http://user:pass@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26",
                                               FALSE, TRUE,  TRUE, "http", "user", "pass", "test.host", 0,    "/fi/../le",        "%3Fa&%26", NULL },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40",
                                               FALSE, TRUE,  TRUE, "http", "user", "pass@", "test.host", 0,    "/fi/../le",        "%3Fa&%26", "%40" },
  /* invalid escaping, invalid_escape disabled */
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",
                                               FALSE, TRUE,  FALSE, NA },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003g%61&%26#%40",
                                               FALSE, TRUE,  FALSE, NA },
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",
                                               FALSE, FALSE, FALSE, NA },
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",
                                               FALSE, FALSE, FALSE, NA },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%4",
                                               FALSE, FALSE, FALSE, NA },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%u434",
                                               FALSE, TRUE,  FALSE, NA },
  { "http//userpass@test.host/file",           FALSE, FALSE, FALSE, NA },
  { "http:userpass@test.host/file",            FALSE, FALSE, FALSE, NA },
  { "http://user:pass@test.host/file?\x1b",    FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        "%1B", NULL },

  /* invalid escaping, invalid_escape, enabled */
  { "http://user:pass@test.host/f%2gile",      TRUE,  FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/f%2gile",        NULL, NULL },
  { "http://user:pass@test.host/f%u123gile",   TRUE,  TRUE,  TRUE, "http", "user", "pass", "test.host", 0,    "/f%u123gile",        NULL, NULL },
  /* IPv4 and IPv6 addresses */
  { "http://127.0.0.1/file",                   FALSE, FALSE, TRUE, "http", NULL,   NULL,   "127.0.0.1", 0,    "/file",        NULL, NULL },
  { "http://[1234::1]/file",                   FALSE, FALSE, TRUE, "http", NULL,   NULL,   "1234::1", 0,    "/file",        NULL, NULL },

  { NULL, 0, 0, 0, NA }
};

BOOST_AUTO_TEST_CASE(test_parse_url)
{
  gint i;

  for (i = 0; test_table[i].url_str; i++)
    {
      test_case(i, test_table[i].url_str, test_table[i].unicode, test_table[i].invalid_escape, test_table[i].valid,
                    test_table[i].scheme, test_table[i].user,  test_table[i].passwd,
                    test_table[i].host, test_table[i].port,  test_table[i].file,
                    test_table[i].query, test_table[i].fragment);
    }
}
