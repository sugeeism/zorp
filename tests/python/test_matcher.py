# vim: ts=8 sts=4 expandtab autoindent

############################################################################
##
## Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
##
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with this program; if not, write to the Free Software Foundation, Inc.,
## 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
##
############################################################################

from Zorp.Core import *
from Zorp.Zorp import quit
from traceback import *
import Zorp.Matcher
import unittest

config.options.kzorp_enabled = FALSE

class MyResolverCache():
    def __init__(self, hosts, server=None):
       self.hostnames = { "blog.balabit" : set(['10.10.40.1']),
                          "intraweb.balabit" : set(['10.10.40.1']),
                          "intra.balabit" : set(['10.10.40.1']),
                          "core.balabit" : set(['10.10.0.1', 'fec0:0:0:b000::ffff']) }
       self.addresses = { "10.10.0.1" : "core.balabit", "10.10.40.1": "blog.balabit"}

    def addHost(self, str):
        pass

    def removeHost(self, str):
        pass

    def shouldUpdate(self):
        return True

    def lookupAddress(self, str):
        """<method internal="yes"/>
        """
        if self.addresses.has_key(str):
            return self.addresses[str]
        else:
            return None

    def lookupHostname(self, str):
        """<method internal="yes"/>
        """
        if self.hostnames.has_key(str):
            return self.hostnames[str]
        else:
            return None

class SubstringMatcher(AbstractMatcher):
    def __init__(self, pattern = ""):
        AbstractMatcher.__init__(self)
        self.pattern = pattern

    def checkMatch(self, str):
        return (str.find(self.pattern) != -1)

class TestCombineMatcher(unittest.TestCase):

    def tearDown(self):
        """Clean up global state since constructing a matcher policy has side effects."""
        import Zorp.Globals
        Zorp.Globals.matchers.clear()

    def test_matcher_policy_getmatcher(self):
        matcher = SubstringMatcher(pattern="a")
        MatcherPolicy("a", matcher)
        self.assertEqual(matcher, Zorp.Matcher.getMatcher("a"))

    def test_substring_matcher(self):
        a = MatcherPolicy("a", SubstringMatcher(pattern="a"))
        Zorp.Matcher.validateMatchers()

        self.assertTrue(a.matcher.checkMatch("alma"))
        self.assertFalse(a.matcher.checkMatch("korte"))

    def test_combine_matcher(self):
        a = MatcherPolicy("a", SubstringMatcher(pattern="a"))
        b = MatcherPolicy("b", SubstringMatcher(pattern="b"))
        c = MatcherPolicy("c", SubstringMatcher(pattern="c"))
        a_or_b = MatcherPolicy("a_or_b", CombineMatcher(expr=[Z_OR, "a", "b"]))
        a_or_b_or_c = MatcherPolicy("a_or_b_or_c", CombineMatcher(expr=[Z_OR, "a", "b", "c"]))
        not_a_or_b_and_c = MatcherPolicy("not_a_or_b_and_c", CombineMatcher( expr=[Z_AND, c, CombineMatcher(expr=[Z_NOT, a_or_b])] ))
        stacked_matcher = MatcherPolicy("stacked", CombineMatcher((Z_AND, c, (Z_NOT, a_or_b)) ))
        Zorp.Matcher.validateMatchers()

        self.assertTrue(a_or_b.matcher.checkMatch("alma"))
        self.assertTrue(a_or_b.matcher.checkMatch("birskorte"))
        self.assertTrue(a_or_b.matcher.checkMatch("birsalma"))
        self.assertFalse(a_or_b.matcher.checkMatch("korte"))

        self.assertFalse(not_a_or_b_and_c.matcher.checkMatch("korte")) # c missing
        self.assertTrue(not_a_or_b_and_c.matcher.checkMatch("cseresznye"))
        self.assertFalse(not_a_or_b_and_c.matcher.checkMatch("almaecet")) # a or b is true
        self.assertFalse(not_a_or_b_and_c.matcher.checkMatch("borecet")) # a or b is true

        self.assertFalse(stacked_matcher.matcher.checkMatch("korte")) # c missing
        self.assertTrue(stacked_matcher.matcher.checkMatch("cseresznye"))
        self.assertFalse(stacked_matcher.matcher.checkMatch("almaecet")) # a or b is true
        self.assertFalse(stacked_matcher.matcher.checkMatch("borecet")) # a or b is true

        self.assertFalse(a_or_b_or_c.matcher.checkMatch("korte"))
        self.assertTrue(a_or_b_or_c.matcher.checkMatch("cseresznye"))
        self.assertTrue(a_or_b_or_c.matcher.checkMatch("almaecet"))
        self.assertTrue(a_or_b_or_c.matcher.checkMatch("borecet"))

class TestDNSMatcher(unittest.TestCase):

    def tearDown(self):
        """Clean up global state since constructing a matcher policy has side effects."""
        import Zorp.Globals
        Zorp.Globals.matchers.clear()

    def test_dns_matcher(self):
        a = MatcherPolicy("a", DNSMatcher(server="10.10.0.1", hosts=("core.balabit", "blog.balabit")))
        Zorp.Matcher.validateMatchers()

        a.matcher.cache = MyResolverCache(None)

        print a.matcher.checkMatch("10.10.0.1")

        self.assertTrue(a.matcher.checkMatch("10.10.0.1"))
        self.assertFalse(a.matcher.checkMatch("10.10.0.2"))

def init(name, virtual_name, is_master):
    unittest.main(argv=('/',))

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
