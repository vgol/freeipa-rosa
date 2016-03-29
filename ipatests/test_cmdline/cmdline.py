# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Base class for all cmdline tests
"""

import nose
import krbV
import distutils.spawn
import os

from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipaserver.plugins.ldap2 import ldap2

# See if our LDAP server is up and we can talk to it over GSSAPI
ccache = krbV.default_context().default_ccache()

try:
    conn = ldap2(api)
    conn.connect(ccache=ccache)
    conn.disconnect()
    server_available = True
except errors.DatabaseError:
    server_available = False
except Exception, e:
    server_available = False

class cmdline_test(XMLRPC_test):
    """
    Base class for all command-line tests
    """
    # some reasonable default command
    command = paths.LS

    @classmethod
    def setup_class(cls):
        # Find the executable in $PATH
        # This is neded because ipautil.run resets the PATH to
        # a system default.
        original_command = cls.command
        if not os.path.isabs(cls.command):
            cls.command = distutils.spawn.find_executable(cls.command)
        # raise an error if the command is missing even if the remote
        # server is not available.
        if not cls.command:
            raise AssertionError(
                'Command %r not available' % original_command
            )
        super(cmdline_test, cls).setup_class()
        if not server_available:
            raise nose.SkipTest(
                'Server not available: %r' % api.env.xmlrpc_uri
            )
