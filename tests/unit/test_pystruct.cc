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

#include <zorp/zpython.h>
#include <zorp/policy.h>
#include <zorp/thread.h>
#include <zorp/sockaddr.h>
#include <zorp/pysockaddr.h>

#include <arpa/inet.h>

/* copied from lib/policy.c, should be changed whenever that one changes */
// struct _ZPolicy
// {
//   gint ref_cnt;
//   gchar *policy_filename;
//   ZPolicyThread *main_thread;
// };

gboolean
call_test_func(const gchar *name, PyObject *args)
{
  PyObject *main_module, *test_func, *res;
  gboolean success = FALSE;

  main_module = PyImport_AddModule("__main__");
  test_func = PyObject_GetAttrString(main_module, (char *) name);

  res = PyObject_CallObject(test_func, args);
  Py_XDECREF(test_func);
  Py_XDECREF(args);
  if (res && z_policy_var_parse(res, "i", &success))
    {
      /* init successful */
    }
  else if (!res)
    {
      PyErr_Print();
    }
  Py_XDECREF(res);
  BOOST_CHECK_MESSAGE(success, "Python test function failed: " << name);
  return TRUE;
}

void
test_sockaddr(void)
{
  ZSockAddr *sa;
  ZPolicyObj *sa_obj;

  sa = z_sockaddr_inet_new("192.168.1.1", 59999);
  sa_obj = z_policy_sockaddr_new(sa);
  z_sockaddr_unref(sa);
  call_test_func("test_sockaddr", z_policy_var_build("(O)", sa_obj));

  z_policy_var_unref(sa_obj);
}

gint counter = 0;

ZPolicyObj *
test_custom_get_value(gpointer user_data, const gchar *name , gpointer value)
{
  g_assert(user_data == (gpointer) 0xdeadbabe);
  g_assert(value == (gpointer) 0xaaffaaff);
  (void) name;
  return PyInt_FromLong(counter++);
}

gint
test_custom_set_value(gpointer user_data, const gchar *name, gpointer value, ZPolicyObj *new_value)
{
  (void) user_data;
  (void) name;
  (void) value;
  (void) new_value;
  counter = 0;
  return 0;
}

void
test_dict(void)
{
  ZPolicyDict *dict;
  ZPolicyObj *str;
  gint simple_int;
  GString *simple_str;
  struct in_addr simple_ip;
  ZPolicyObj *simple_obj;
  gchar simple_cstr[64] = "huligan";
  ZSockAddr *sa;
  gchar bytearray[128] = "bytearray";

  simple_int = 55555;
  simple_str = g_string_new("abcdef");

  inet_aton("192.168.5.6", &simple_ip);

  sa = z_sockaddr_inet_new("192.168.1.1", 59999);
  simple_obj = z_policy_sockaddr_new(sa);
  z_sockaddr_unref(sa);

  dict = z_policy_dict_new();

  z_policy_dict_register(dict, Z_VT_INT, "simple_int", Z_VF_RW, &simple_int);
  z_policy_dict_register(dict, Z_VT_INT, "literal_int", Z_VF_RW | Z_VF_LITERAL, 66666);
  z_policy_dict_register(dict, Z_VT_STRING, "simple_str", Z_VF_RW, simple_str);
  z_policy_dict_register(dict, Z_VT_STRING, "literal_str", Z_VF_RW | Z_VF_LITERAL, "abrakadabra");
  z_policy_dict_register(dict, Z_VT_CSTRING, "simple_cstr", Z_VF_RW, simple_cstr, sizeof(simple_cstr));
  z_policy_dict_register(dict, Z_VT_CSTRING, "literal_cstr_ro", Z_VF_READ | Z_VF_LITERAL, "viharkeszulodik", 64);
  z_policy_dict_register(dict, Z_VT_CSTRING, "literal_cstr", Z_VF_RW | Z_VF_LITERAL | Z_VF_DUP, "viharkeszulodik2", 64);
  z_policy_dict_register(dict, Z_VT_IP, "simple_ip", Z_VF_RW, &simple_ip);
  z_policy_dict_register(dict, Z_VT_IP, "simple_ip_str", Z_VF_RW | Z_VF_IP_STR, &simple_ip);
  z_policy_dict_register(dict, Z_VT_ALIAS, "alias", Z_VF_RW, "simple_str");
  z_policy_dict_register(dict, Z_VT_OBJECT, "simple_obj", Z_VF_RW, &simple_obj);
                           // get, set, free, user_data, user_data_free
  z_policy_dict_register(dict, Z_VT_CUSTOM, "custom", Z_VF_RW, (gpointer) 0xaaffaaff, test_custom_get_value, test_custom_set_value, NULL, (gpointer) 0xdeadbabe, NULL);
  z_policy_dict_register(dict, Z_VT_BYTEARRAY, "bytearray_dup", Z_VF_READ | Z_VF_LITERAL | Z_VF_DUP, bytearray, sizeof(bytearray));
  z_policy_dict_register(dict, Z_VT_BYTEARRAY, "bytearray", Z_VF_READ, bytearray, sizeof(bytearray));
  /*
                           Z_VT_IP6,
                           Z_VT_HASH,
                           Z_VT_METHOD,
                           Z_VT_DIMHASH,
  */

  str = z_policy_struct_new(dict, Z_PST_SHARED);
  call_test_func("test_dict", z_policy_var_build("(O)", str));
  z_policy_var_unref(str);

}

BOOST_AUTO_TEST_CASE(test_pystruct)
{
  gchar *srcdir = getenv("srcdir");
  gchar policy_file[512];
  ZPolicy *policy;
  FILE *script;

  g_snprintf(policy_file, sizeof(policy_file), "%s/pystruct.py", srcdir ? srcdir : ".");
  z_thread_init();

  BOOST_CHECK_MESSAGE(z_python_init(), "Python initialization failed");
  policy = z_policy_new(policy_file);
  z_policy_boot(policy);

  script = fopen(policy->policy_filename, "r");
  BOOST_CHECK_MESSAGE(script, "Error loading test script");

  z_policy_thread_acquire(policy->main_thread);
  BOOST_CHECK_MESSAGE(PyRun_SimpleFile(script, policy->policy_filename) != -1, "Parsing failed");
  fclose(script);

  test_sockaddr();
  test_dict();

  z_policy_thread_release(policy->main_thread);
  //z_policy_unref(policy);

  z_thread_destroy();
  z_python_destroy();
}
