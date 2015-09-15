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

#undef ENABLE_TRACE
#include "../smtp.cc"

static SmtpProxy *self;

/**
 * @brief Test smtp_request_parse() with various input vectors
 */
BOOST_AUTO_TEST_CASE(test_request_parse)
{
  z_thread_init();
  z_log_init("smtp_request", ZLF_STDERR);
  z_python_init();

  self = Z_NEW_COMPAT(Z_CLASS(SmtpProxy), SmtpProxy);
  g_strlcpy(self->super.session_id, "test/telnet:1", sizeof(self->super.session_id));
  self->request = g_string_new("");
  self->request_param = g_string_new("");

#define TEST_REQUEST_FAILS(_line) do {                                 \
    BOOST_CHECK(smtp_parse_request(self, _line, strlen(_line)) == FALSE); \
  } while (0)

  TEST_REQUEST_FAILS("");
  TEST_REQUEST_FAILS(" HELO");

#define TEST_REQUEST(_line, _request, _param) do {                    \
    BOOST_CHECK(smtp_parse_request(self, _line, strlen(_line)));         \
    BOOST_CHECK(!strcmp(self->request->str, _request));                \
    BOOST_CHECK(!strcmp(self->request_param->str, _param));            \
  } while (0)

  TEST_REQUEST("HELO", "HELO", "");
  TEST_REQUEST("HELO ", "HELO", "");
  TEST_REQUEST("HELO  ", "HELO", "");
  TEST_REQUEST("EHLO example.domain.com", "EHLO", "example.domain.com");
  TEST_REQUEST("EHLO  example.domain.com", "EHLO", "example.domain.com");

#undef TEST_REQUEST
#undef TEST_REQUEST_FAILS
}
