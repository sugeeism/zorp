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
#include "../smtpcmd.cc"

BOOST_AUTO_TEST_CASE(test_smtp_parse_atom)
{
  gchar *end, *str;

#define OFFSET_TO_PTR(str, offset) (&str[offset])

  /* empty string is OK */
  str = "";
  BOOST_CHECK(smtp_parse_atom(NULL, str, &end));
  BOOST_CHECK(end == str);

  /* should stop at end of string */
  str = "valid";
  BOOST_CHECK(smtp_parse_atom(NULL, str, &end));
  BOOST_CHECK(end == OFFSET_TO_PTR(str, strlen(str)));

  /* special characters */
#define TEST_SPECIAL(chr) do {                  \
    str = chr;					\
    BOOST_CHECK(smtp_parse_atom(NULL, str, &end));	\
    BOOST_CHECK(end == str);			\
    str = "valid" chr "alsovalid";              \
    BOOST_CHECK(smtp_parse_atom(NULL, str, &end)); \
    BOOST_CHECK_EQUAL(end - str, strstr(str, chr) - str);     \
  } while (0)

  TEST_SPECIAL("(");
  TEST_SPECIAL(")");
  TEST_SPECIAL("<");
  TEST_SPECIAL(">");
  TEST_SPECIAL("@");
  TEST_SPECIAL(",");
  TEST_SPECIAL(";");
  TEST_SPECIAL(":");
  TEST_SPECIAL("\\");
  TEST_SPECIAL("\"");
  TEST_SPECIAL(".");
  TEST_SPECIAL("[");
  TEST_SPECIAL("]");
  TEST_SPECIAL(" ");

#undef TEST_SPECIAL
}

BOOST_AUTO_TEST_CASE(test_smtp_parse_domain)
{
  gchar *end;

#define TEST_DOMAIN(str, expected) do {                  \
    gchar *_end;                                         \
    BOOST_CHECK(smtp_parse_domain(NULL, str, &_end));       \
    BOOST_CHECK_EQUAL(_end - str, strlen(expected));   \
  } while (0)

  /* must contain at least one valid character */
  BOOST_CHECK(!smtp_parse_domain(NULL, "", &end));
  BOOST_CHECK(!smtp_parse_domain(NULL, " invalid.example.com", &end));
  TEST_DOMAIN("a", "a");
  TEST_DOMAIN("a ", "a");

  /* parts may be separated by dots */
  TEST_DOMAIN("domain.name.example", "domain.name.example");
  TEST_DOMAIN("domain .name.example", "domain");
}
