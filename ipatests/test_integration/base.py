# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

"""Base class for FreeIPA integration tests"""

import pytest

from ipapython.ipa_log_manager import log_mgr
from ipatests.test_integration import tasks
from pytest_sourceorder import ordered

log = log_mgr.get_logger(__name__)


@ordered
@pytest.mark.usefixtures('mh')
@pytest.mark.usefixtures('integration_logs')
class IntegrationTest(object):
    num_replicas = 0
    num_clients = 0
    num_ad_domains = 0
    required_extra_roles = []
    topology = None

    @classmethod
    def setup_class(cls):
        pass

    @classmethod
    def host_by_role(cls, role):
        for domain in cls.get_domains():
            try:
                return domain.host_by_role(role)
            except LookupError:
                pass
        raise LookupError(role)

    @classmethod
    def get_all_hosts(cls):
        return ([cls.master] + cls.replicas + cls.clients +
                map(cls.host_by_role, cls.required_extra_roles))

    @classmethod
    def get_domains(cls):
        return [cls.domain] + cls.ad_domains

    @classmethod
    def install(cls, mh):
        if cls.topology is None:
            return
        else:
            tasks.install_topo(cls.topology,
                               cls.master, cls.replicas, cls.clients)
    @classmethod
    def teardown_class(cls):
        pass

    @classmethod
    def uninstall(cls, mh):
        tasks.uninstall_master(cls.master)
        for replica in cls.replicas:
            tasks.uninstall_master(replica)
        for client in cls.clients:
            tasks.uninstall_client(client)


IntegrationTest.log = log_mgr.get_logger(IntegrationTest())
