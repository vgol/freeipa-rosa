# Authors:
#   Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2011  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Test the `ipapython/ipautil.py` module.
"""

import nose

from ipapython import ipautil


def make_ipaddress_checker(addr, words=None, prefixlen=None):
    def check_ipaddress():
        try:
            ip = ipautil.CheckedIPAddress(addr, match_local=False)
            assert ip.words == words and ip.prefixlen == prefixlen
        except:
            assert words is None and prefixlen is None
    check_ipaddress.description = "Test IP address parsing and verification (%s)" % addr
    return check_ipaddress


def test_ip_address():
    addrs = [
        ('10.11.12.13',     (10, 11, 12, 13),   8),
        ('10.11.12.13/14',  (10, 11, 12, 13),   14),
        ('10.11.12.13%zoneid',),
        ('10.11.12.13%zoneid/14',),
        ('10.11.12.1337',),
        ('10.11.12.13/33',),
        ('127.0.0.1',),
        ('241.1.2.3',),
        ('169.254.1.2',),
        ('10.11.12.0/24',),
        ('224.5.6.7',),
        ('10.11.12.255/24',),

        ('2001::1',         (0x2001, 0, 0, 0, 0, 0, 0, 1), 64),
        ('2001::1/72',      (0x2001, 0, 0, 0, 0, 0, 0, 1), 72),
        ('2001::1%zoneid',  (0x2001, 0, 0, 0, 0, 0, 0, 1), 64),
        ('2001::1%zoneid/72',),
        ('2001::1beef',),
        ('2001::1/129',),
        ('::1',),
        ('6789::1',),
        ('fe89::1',),
        ('2001::/64',),
        ('ff01::1',),

        ('junk',)
    ]

    for addr in addrs:
        yield make_ipaddress_checker(*addr)


class TestCIDict(object):
    def setup(self):
        self.cidict = ipautil.CIDict()
        self.cidict["Key1"] = "val1"
        self.cidict["key2"] = "val2"
        self.cidict["KEY3"] = "VAL3"

    def test_init(self):
        cidict = ipautil.CIDict()
        assert dict(cidict.items()) == {}
        cidict = ipautil.CIDict([('a', 2), ('b', 3), ('C', 4)])
        assert dict(cidict.items()) == {'a': 2, 'b': 3, 'C': 4}
        cidict = ipautil.CIDict([('a', 2), ('b', None)], b=3, C=4)
        assert dict(cidict.items()) == {'a': 2, 'b': 3, 'C': 4}
        cidict = ipautil.CIDict({'a': 2, 'b': None}, b=3, C=4)
        assert dict(cidict.items()) == {'a': 2, 'b': 3, 'C': 4}
        cidict = ipautil.CIDict(a=2, b=3, C=4)
        assert dict(cidict.items()) == {'a': 2, 'b': 3, 'C': 4}

    def test_len(self):
        nose.tools.assert_equal(3, len(self.cidict))

    def test_getitem(self):
        nose.tools.assert_equal("val1", self.cidict["Key1"])
        nose.tools.assert_equal("val1", self.cidict["key1"])
        nose.tools.assert_equal("val2", self.cidict["KEY2"])
        nose.tools.assert_equal("VAL3", self.cidict["key3"])
        nose.tools.assert_equal("VAL3", self.cidict["KEY3"])
        with nose.tools.assert_raises(KeyError):
            self.cidict["key4"]

    def test_get(self):
        nose.tools.assert_equal("val1", self.cidict.get("Key1"))
        nose.tools.assert_equal("val1", self.cidict.get("key1"))
        nose.tools.assert_equal("val2", self.cidict.get("KEY2"))
        nose.tools.assert_equal("VAL3", self.cidict.get("key3"))
        nose.tools.assert_equal("VAL3", self.cidict.get("KEY3"))
        nose.tools.assert_equal("default", self.cidict.get("key4", "default"))

    def test_setitem(self):
        self.cidict["key4"] = "val4"
        nose.tools.assert_equal("val4", self.cidict["key4"])
        self.cidict["KEY4"] = "newval4"
        nose.tools.assert_equal("newval4", self.cidict["key4"])

    def test_del(self):
        assert self.cidict.has_key("Key1")
        del(self.cidict["Key1"])
        assert not self.cidict.has_key("Key1")

        assert self.cidict.has_key("key2")
        del(self.cidict["KEY2"])
        assert not self.cidict.has_key("key2")

    def test_clear(self):
        nose.tools.assert_equal(3, len(self.cidict))
        self.cidict.clear()
        nose.tools.assert_equal(0, len(self.cidict))
        assert self.cidict == {}
        assert self.cidict.keys() == []
        assert self.cidict.values() == []
        assert self.cidict.items() == []
        assert self.cidict._keys == {}

    def test_copy(self):
        copy = self.cidict.copy()
        assert copy == self.cidict
        nose.tools.assert_equal(3, len(copy))
        assert copy.has_key("Key1")
        assert copy.has_key("key1")
        nose.tools.assert_equal("val1", copy["Key1"])

    def test_haskey(self):
        assert self.cidict.has_key("KEY1")
        assert self.cidict.has_key("key2")
        assert self.cidict.has_key("key3")

        assert not self.cidict.has_key("Key4")

    def test_contains(self):
        assert "KEY1" in self.cidict
        assert "key2" in self.cidict
        assert "key3" in self.cidict

        assert "Key4" not in self.cidict

    def test_items(self):
        items = self.cidict.items()
        nose.tools.assert_equal(3, len(items))
        items_set = set(items)
        assert ("Key1", "val1") in items_set
        assert ("key2", "val2") in items_set
        assert ("KEY3", "VAL3") in items_set

        assert self.cidict.items() == list(self.cidict.iteritems()) == zip(
            self.cidict.iterkeys(), self.cidict.itervalues())

    def test_iter(self):
        items = []
        assert list(self.cidict) == list(self.cidict.keys())
        assert sorted(self.cidict) == sorted(['Key1', 'key2', 'KEY3'])

    def test_iteritems(self):
        items = []
        for (k,v) in self.cidict.iteritems():
            items.append((k,v))
        nose.tools.assert_equal(3, len(items))
        items_set = set(items)
        assert ("Key1", "val1") in items_set
        assert ("key2", "val2") in items_set
        assert ("KEY3", "VAL3") in items_set

    def test_iterkeys(self):
        keys = []
        for k in self.cidict.iterkeys():
            keys.append(k)
        nose.tools.assert_equal(3, len(keys))
        keys_set = set(keys)
        assert "Key1" in keys_set
        assert "key2" in keys_set
        assert "KEY3" in keys_set

    def test_itervalues(self):
        values = []
        for k in self.cidict.itervalues():
            values.append(k)
        nose.tools.assert_equal(3, len(values))
        values_set = set(values)
        assert "val1" in values_set
        assert "val2" in values_set
        assert "VAL3" in values_set

    def test_keys(self):
        keys = self.cidict.keys()
        nose.tools.assert_equal(3, len(keys))
        keys_set = set(keys)
        assert "Key1" in keys_set
        assert "key2" in keys_set
        assert "KEY3" in keys_set

        assert self.cidict.keys() == list(self.cidict.iterkeys())

    def test_values(self):
        values = self.cidict.values()
        nose.tools.assert_equal(3, len(values))
        values_set = set(values)
        assert "val1" in values_set
        assert "val2" in values_set
        assert "VAL3" in values_set

        assert self.cidict.values() == list(self.cidict.itervalues())

    def test_update(self):
        newdict = { "KEY2": "newval2",
                    "key4": "val4" }
        self.cidict.update(newdict)
        nose.tools.assert_equal(4, len(self.cidict))

        items = self.cidict.items()
        nose.tools.assert_equal(4, len(items))
        items_set = set(items)
        assert ("Key1", "val1") in items_set
        # note the update "overwrites" the case of the key2
        assert ("KEY2", "newval2") in items_set
        assert ("KEY3", "VAL3") in items_set
        assert ("key4", "val4") in items_set

    def test_update_dict_and_kwargs(self):
        self.cidict.update({'a': 'va', 'b': None}, b='vb', key2='v2')
        assert dict(self.cidict.items()) == {
            'a': 'va', 'b': 'vb',
            'Key1': 'val1', 'key2': 'v2', 'KEY3': 'VAL3'}

    def test_update_list_and_kwargs(self):
        self.cidict.update([('a', 'va'), ('b', None)], b='vb', key2='val2')
        assert dict(self.cidict.items()) == {
            'a': 'va', 'b': 'vb',
            'Key1': 'val1', 'key2': 'val2', 'KEY3': 'VAL3'}

    def test_update_duplicate_values_dict(self):
        with nose.tools.assert_raises(ValueError):
            self.cidict.update({'a': 'va', 'A': None, 'b': 3})

    def test_update_duplicate_values_list(self):
        with nose.tools.assert_raises(ValueError):
            self.cidict.update([('a', 'va'), ('A', None), ('b', 3)])

    def test_update_duplicate_values_kwargs(self):
        with nose.tools.assert_raises(ValueError):
            self.cidict.update(a='va', A=None, b=3)

    def test_update_kwargs(self):
        self.cidict.update(b='vb', key2='val2')
        assert dict(self.cidict.items()) == {
            'b': 'vb', 'Key1': 'val1', 'key2': 'val2', 'KEY3': 'VAL3'}

    def test_setdefault(self):
        nose.tools.assert_equal("val1", self.cidict.setdefault("KEY1", "default"))

        assert not self.cidict.has_key("KEY4")
        nose.tools.assert_equal("default", self.cidict.setdefault("KEY4", "default"))
        assert self.cidict.has_key("KEY4")
        nose.tools.assert_equal("default", self.cidict["key4"])

        assert not self.cidict.has_key("KEY5")
        nose.tools.assert_equal(None, self.cidict.setdefault("KEY5"))
        assert self.cidict.has_key("KEY5")
        nose.tools.assert_equal(None, self.cidict["key5"])

    def test_pop(self):
        nose.tools.assert_equal("val1", self.cidict.pop("KEY1", "default"))
        assert not self.cidict.has_key("key1")

        nose.tools.assert_equal("val2", self.cidict.pop("KEY2"))
        assert not self.cidict.has_key("key2")

        nose.tools.assert_equal("default", self.cidict.pop("key4", "default"))
        with nose.tools.assert_raises(KeyError):
            self.cidict.pop("key4")

    def test_popitem(self):
        items = set(self.cidict.items())
        nose.tools.assert_equal(3, len(self.cidict))

        item = self.cidict.popitem()
        nose.tools.assert_equal(2, len(self.cidict))
        assert item in items
        items.discard(item)

        item = self.cidict.popitem()
        nose.tools.assert_equal(1, len(self.cidict))
        assert item in items
        items.discard(item)

        item = self.cidict.popitem()
        nose.tools.assert_equal(0, len(self.cidict))
        assert item in items
        items.discard(item)

    def test_fromkeys(self):
        dct = ipautil.CIDict.fromkeys(('A', 'b', 'C'))
        assert sorted(dct.keys()) == sorted(['A', 'b', 'C'])
        assert sorted(dct.values()) == [None] * 3


class TestTimeParser(object):
    def test_simple(self):
        timestr = "20070803"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(2007, time.year)
        nose.tools.assert_equal(8, time.month)
        nose.tools.assert_equal(3, time.day)
        nose.tools.assert_equal(0, time.hour)
        nose.tools.assert_equal(0, time.minute)
        nose.tools.assert_equal(0, time.second)

    def test_hour_min_sec(self):
        timestr = "20051213141205"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(2005, time.year)
        nose.tools.assert_equal(12, time.month)
        nose.tools.assert_equal(13, time.day)
        nose.tools.assert_equal(14, time.hour)
        nose.tools.assert_equal(12, time.minute)
        nose.tools.assert_equal(5, time.second)

    def test_fractions(self):
        timestr = "2003092208.5"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(2003, time.year)
        nose.tools.assert_equal(9, time.month)
        nose.tools.assert_equal(22, time.day)
        nose.tools.assert_equal(8, time.hour)
        nose.tools.assert_equal(30, time.minute)
        nose.tools.assert_equal(0, time.second)

        timestr = "199203301544,25"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(1992, time.year)
        nose.tools.assert_equal(3, time.month)
        nose.tools.assert_equal(30, time.day)
        nose.tools.assert_equal(15, time.hour)
        nose.tools.assert_equal(44, time.minute)
        nose.tools.assert_equal(15, time.second)

        timestr = "20060401185912,8"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(2006, time.year)
        nose.tools.assert_equal(4, time.month)
        nose.tools.assert_equal(1, time.day)
        nose.tools.assert_equal(18, time.hour)
        nose.tools.assert_equal(59, time.minute)
        nose.tools.assert_equal(12, time.second)
        nose.tools.assert_equal(800000, time.microsecond)

    def test_time_zones(self):
        timestr = "20051213141205Z"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(0, time.tzinfo.houroffset)
        nose.tools.assert_equal(0, time.tzinfo.minoffset)
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        nose.tools.assert_equal(0, offset.seconds)

        timestr = "20051213141205+0500"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(5, time.tzinfo.houroffset)
        nose.tools.assert_equal(0, time.tzinfo.minoffset)
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        nose.tools.assert_equal(5 * 60 * 60, offset.seconds)

        timestr = "20051213141205-0500"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(-5, time.tzinfo.houroffset)
        nose.tools.assert_equal(0, time.tzinfo.minoffset)
        # NOTE - the offset is always positive - it's minutes
        #        _east_ of UTC
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        nose.tools.assert_equal((24 - 5) * 60 * 60, offset.seconds)

        timestr = "20051213141205-0930"

        time = ipautil.parse_generalized_time(timestr)
        nose.tools.assert_equal(-9, time.tzinfo.houroffset)
        nose.tools.assert_equal(-30, time.tzinfo.minoffset)
        offset = time.tzinfo.utcoffset(time.tzinfo.dst())
        nose.tools.assert_equal(((24 - 9) * 60 * 60) - (30 * 60), offset.seconds)
