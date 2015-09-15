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

#ifndef TESTS_UNIT_HELPERS_ZPROXY
#define TESTS_UNIT_HELPERS_ZPROXY

#include <zorp/proxy.h>
#include <zorp/zpython.h>
#include <zorp/policy.h>
#include <zorp/pyproxy.h>
#include <zorp/registry.h>

/**
 * Init proxy environment
 */
void
init_environment();

/**
 * Create a ZProxy* instance with special python policy.
 */
ZProxy*
get_proxy_with_policy(const char* policy_source, ZPolicy **new_policy, PyObject **new_proxy_instance, ZClass *proxy_class);

/**
 * After test is finished, it closes python interpreter.
 */
void
leave_zproxy_test();

/**
 * Fetch an attribute of the policy proxy instance as a python object with a new reference
 */
PyObject*
fetch_policy_attribute(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name);

/**
 * Fetch a string attribute of the policy proxy instance in char*
 */
char*
fetch_policy_attribute_as_string(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name);

/**
 * Fetch an attribute of the policy proxy instance, evaluated as a boolean
 */
gboolean
fetch_policy_attribute_as_boolean(ZPolicy *policy, PyObject *proxy_instance, const char* attribute_name);

/**
 * Call a method of the policy proxy instance without arguments.
 */
void
call_policy_method(ZPolicy *policy, PyObject *proxy_instance, char* method_name);

#endif /* TESTS_UNIT_HELPERS_ZPROXY*/
