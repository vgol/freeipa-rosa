# Authors:
#   Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

import os
import sys
import nose
from nss import nss
from ipalib.x509 import initialize_nss_database

from ipaserver.install.ipa_otptoken_import import PSKCDocument, ValidationError

basename = os.path.join(os.path.dirname(__file__), "data")

class test_otptoken_import(object):

    def teardown(self):
        initialize_nss_database()

    def test_figure3(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure3.xml"))
        assert doc.keyname is None
        assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
            [(u'12345678', {
                'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                'ipatokenvendor': u'Manufacturer',
                'ipatokenserial': u'987654321',
                'ipatokenhotpcounter': 0L,
                'ipatokenotpdigits': 8,
                'type': u'hotp',
                })]

    def test_figure4(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure4.xml"))
        assert doc.keyname is None
        try:
            [(t.id, t.options) for t in doc.getKeyPackages()]
        except ValidationError: # Referenced keys are not supported.
            pass
        else:
            assert False

    def test_figure5(self):
        doc = PSKCDocument(os.path.join(basename, "pskc-figure5.xml"))
        assert doc.keyname is None
        try:
            [(t.id, t.options) for t in doc.getKeyPackages()]
        except ValidationError: # PIN Policy is not supported.
            pass
        else:
            assert False

    def test_figure6(self):
        nss.nss_init_nodb()
        try:
            doc = PSKCDocument(os.path.join(basename, "pskc-figure6.xml"))
            assert doc.keyname == 'Pre-shared-key'
            doc.setKey('12345678901234567890123456789012'.decode('hex'))
            assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
                [(u'12345678', {
                    'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                    'ipatokenvendor': u'Manufacturer',
                    'ipatokenserial': u'987654321',
                    'ipatokenhotpcounter': 0L,
                    'ipatokenotpdigits': 8,
                    'type': u'hotp'})]
        finally:
            nss.nss_shutdown()

    def test_figure7(self):
        nss.nss_init_nodb()
        try:
            doc = PSKCDocument(os.path.join(basename, "pskc-figure7.xml"))
            assert doc.keyname == 'My Password 1'
            doc.setKey('qwerty')
            assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
                [(u'123456', {
                    'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                    'ipatokenvendor': u'TokenVendorAcme',
                    'ipatokenserial': u'987654321',
                    'ipatokenotpdigits': 8,
                    'type': u'hotp'})]
        finally:
            nss.nss_shutdown()

    def test_figure8(self):
        nss.nss_init_nodb()
        try:
            doc = PSKCDocument(os.path.join(basename, "pskc-figure8.xml"))
        except NotImplementedError: # X.509 is not supported.
            pass
        else:
            assert False
        finally:
            nss.nss_shutdown()

    def test_invalid(self):
        nss.nss_init_nodb()
        try:
            doc = PSKCDocument(os.path.join(basename, "pskc-invalid.xml"))
        except ValueError: # File is invalid.
            pass
        else:
            assert False
        finally:
            nss.nss_shutdown()

    def test_mini(self):
        nss.nss_init_nodb()
        try:
            doc = PSKCDocument(os.path.join(basename, "pskc-mini.xml"))
            [(t.id, t.options) for t in doc.getKeyPackages()]
        except ValidationError: # Unsupported token type.
            pass
        else:
            assert False
        finally:
            nss.nss_shutdown()

    def test_full(self):
        nss.nss_init_nodb()
        try:
            doc = PSKCDocument(os.path.join(basename, "full.xml"))
            assert [(t.id, t.options) for t in doc.getKeyPackages()] == \
                [(u'KID1', {
                    'ipatokenotpkey': u'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                    'ipatokennotafter': u'20060531000000Z',
                    'ipatokennotbefore': u'20060501000000Z',
                    'ipatokenserial': u'SerialNo-IssueNo',
                    'ipatokentotpclockoffset': 60000,
                    'ipatokenotpalgorithm': u'sha1',
                    'ipatokenvendor': u'iana.dummy',
                    'description': u'FriendlyName',
                    'ipatokentotptimestep': 200,
                    'ipatokenhotpcounter': 0L,
                    'ipatokenmodel': u'Model',
                    'ipatokenotpdigits': 8,
                    'type': u'hotp',
                })]
        finally:
            nss.nss_shutdown()
