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
 *
 * The policy's class name MUST BE TestProxy!
 *
 * Example:
 *   ZProxy* proxy = get_proxy_with_policy(
 *     "class TestProxy(object):\n"
 *     "  def processEvent(self, type, event):\n"
 *     "    self.type = type\n"
 *     "    self.event = event\n");
 */
ZProxy*
get_proxy_with_policy(const char* policy_source);

/**
 * After test is finished, it closes python interpreter.
 */
void
leave_zproxy_test();

/**
 * Fetch an attribute of the TestProxy python object
 */
PyObject*
fetch_policy_attribute(const char* attribute_name);

/**
 * Fetch a string attribute of the TestProxy in char*
 */
char*
fetch_policy_attribute_as_string(const char* attribute_name);

#endif /* TESTS_UNIT_HELPERS_ZPROXY*/
