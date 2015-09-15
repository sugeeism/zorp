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

#include "../smtp.h"

SmtpProxy *dummy;

int exit_code = 0;

#define SAFE_STR(x)  ((x) ? x : "(NULL)")

void
test_case(gchar *path, gchar *email, gboolean expected)
{
  GString *result = g_string_sized_new(128);
  gchar *end = 0;

  BOOST_CHECK_MESSAGE(smtp_sanitize_address(dummy, result, path, TRUE, &end) == expected, "failure, different parsing, path=" << path << ", email=" << email << ", result=" << result->str << ", end=" << end);
  BOOST_CHECK_MESSAGE(expected && (strcmp(result->str, email) == 0) || !expected, "failure, different email, path=" << path <<", email=" << email << ", end=" << end);
}

BOOST_AUTO_TEST_CASE(test_sanitize_addr)
{
  dummy = (SmtpProxy *) z_object_new(Z_CLASS(SmtpProxy));
  dummy->append_domain = g_string_sized_new(0);
  /* z_charset_parse(&dummy.local_part, "a-zA-Z0-9\\-=._"); */
  test_case("<bazsi@balabit.hu>", "bazsi@balabit.hu", TRUE);
  test_case("<>", "", TRUE);
  test_case("<@hop1,@hop2,@hop3:bazsi@balabit.hu>", "bazsi@balabit.hu", TRUE);
  test_case("<@:bazsi@balabit.hu>", NULL, FALSE);
  test_case("<:bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1@bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1\"bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1:;bazsi@balabit.hu>", NULL, FALSE);
  test_case("<@hop1,bazsi@balabit.hu>", NULL, FALSE);
  test_case("<bazsi@balabit.hu", NULL, FALSE);
  test_case("bazsi@balabit.hu>", NULL, FALSE);
  test_case("bazsi@balabit.hu", NULL, FALSE);
  test_case("<bazsibalabit.hu>", NULL, FALSE);
  test_case("<\"balazs scheidler\"@balabit.hu>", "\"balazs scheidler\"@balabit.hu", TRUE);
  test_case("<\"balazs scheidler\"@[1.2.3.4]>", "\"balazs scheidler\"@[1.2.3.4]", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@[1.2.3.4]>", "\"balazs scheidler\"@[1.2.3.4]", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@[domain literal]>", "\"balazs scheidler\"@[domain literal]", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@#123456>", "\"balazs scheidler\"@#123456", TRUE);
  test_case("<@hop1.domain,@hop2.domain:\"balazs scheidler\"@#123456z>", NULL, FALSE);
  test_case("<bounce-debian-gcc=asd=balabit.hu@lists.debian.org> SIZE=10037", "bounce-debian-gcc=asd=balabit.hu@lists.debian.org", TRUE);
  test_case("bazsi@balabit.hu", NULL, FALSE);
  test_case("<bazsi@balabit.hu", NULL, FALSE);
  test_case("bazsi@balabit.hu>", NULL, FALSE);
  dummy->permit_omission_of_angle_brackets = TRUE;
  printf("------\n");
  test_case("bazsi@balabit.hu", "bazsi@balabit.hu", TRUE);
  test_case("<bazsi@balabit.hu>", "bazsi@balabit.hu", TRUE);
  test_case("<bazsi@balabit.hu", "bazsi@balabit.hu", FALSE);
  test_case("bazsi@balabit.hu>", "bazsi@balabit.hu", FALSE);
  test_case("bounce-debian-gcc=asd=balabit.hu@lists.debian.org SIZE=10037", "bounce-debian-gcc=asd=balabit.hu@lists.debian.org", TRUE);
}
