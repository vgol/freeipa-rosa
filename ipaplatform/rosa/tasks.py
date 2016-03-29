# Copyright (C) 2015 ROSA, based on SUSE file
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
This module contains default ROSA-specific implementations of system tasks.
"""

from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.rosa.rosaac import AuthConfig


class RosaTaskNamespace(RedHatTaskNamespace):
    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        # FIXME: Implement the method.
        print "restore_pre_ipa_client_configuration called"

    def set_nisdomain(self, nisdomain):
        # FIXME: Implement the method.
        print "set_nisdomain called"

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore):
        auth_config = AuthConfig()

        if sssd:
            statestore.backup_state('rosaac', 'sssd', True)
            statestore.backup_state('rosaac', 'sssdauth', True)
            auth_config.options.enablesssd = True
            auth_config.options.enablesssdauth = True
        else:
            statestore.backup_state('rosaac', 'ldap', True)
            auth_config.options.enableldap = True
            auth_config.options.enableforcelegacy = True

        if mkhomedir:
            statestore.backup_state('rosaac', 'mkhomedir', True)
            auth_config.options.enablemkhomedir = True

        auth_config.run()

    def modify_pam_to_use_krb5(self, statestore):
        # FIXME: Implement the method.
        print "modify_pam_to_use_krb5 called"


tasks = RosaTaskNamespace()
