# Authors:
#   Tomas Babej <tbabej@redhat.com>
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

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.tasks import clear_sssd_cache


class TestSudo(IntegrationTest):
    """
    Test Sudo
    http://www.freeipa.org/page/V4/Sudo_Integration#Test_Plan
    """
    num_clients = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        super(TestSudo, cls).install(mh)

        cls.client = cls.clients[0]

        for i in range(1, 3):
            # Add 1. and 2. testing user
            cls.master.run_command(['ipa', 'user-add',
                                     'testuser%d' % i,
                                     '--first', 'Test',
                                     '--last', 'User%d' % i])

            # Add 1. and 2. testing groups
            cls.master.run_command(['ipa', 'group-add',
                                     'testgroup%d' % i,
                                     '--desc', '"%d. testing group"' % i])

            # Add respective members to each group
            cls.master.run_command(['ipa', 'group-add-member',
                                     'testgroup%d' % i,
                                     '--users', 'testuser%d' % i])

        # Add hostgroup containing the client
        cls.master.run_command(['ipa', 'hostgroup-add',
                                 'testhostgroup',
                                 '--desc', '"Contains client"'])

        # Add the client to the host group
        cls.master.run_command(['ipa', 'hostgroup-add-member',
                                 'testhostgroup',
                                 '--hosts', cls.client.hostname])

        # Create local user and local group he's member of
        cls.client.run_command(['groupadd', 'localgroup'])
        cls.client.run_command(['useradd',
                                '-M',
                                '-G', 'localgroup',
                                'localuser'])

    @classmethod
    def uninstall(cls, mh):
        cls.client.run_command(['groupdel', 'localgroup'], raiseonerr=False)
        cls.client.run_command(['userdel', 'localuser'], raiseonerr=False)
        super(TestSudo, cls).uninstall(mh)

    def list_sudo_commands(self, user, raiseonerr=False, verbose=False):
        clear_sssd_cache(self.client)
        list_flag = '-ll' if verbose else '-l'
        return self.client.run_command('su -c "sudo %s" %s' % (list_flag, user),
                                       raiseonerr=raiseonerr)

    def reset_rule_categories(self, safe_delete=True):
        if safe_delete:
            # Remove and then add the rule back, since the deletion of some
            # entries might cause setting categories to ALL to fail
            # and therefore cause false negatives in the tests
            self.master.run_command(['ipa', 'sudorule-del', 'testrule'])
            self.master.run_command(['ipa', 'sudorule-add', 'testrule'])
            self.master.run_command(['ipa', 'sudorule-add-option',
                                     'testrule',
                                     '--sudooption', "!authenticate"])

        # Reset testrule to allow everything
        result = self.master.run_command(['ipa', 'sudorule-mod',
                                          'testrule',
                                          '--usercat=all',
                                          '--hostcat=all',
                                          '--cmdcat=all',
                                          '--runasusercat=all',
                                          '--runasgroupcat=all'],
                                          raiseonerr=False)

        return result

    def test_nisdomainname(self):
        result = self.client.run_command('nisdomainname')
        assert self.client.domain.name in result.stdout_text

    def test_add_sudo_commands(self):
        # Group: Readers
        self.master.run_command(['ipa', 'sudocmd-add', '/usr/bin/cat'])
        self.master.run_command(['ipa', 'sudocmd-add', '/usr/bin/tail'])

        # No group
        self.master.run_command(['ipa', 'sudocmd-add', '/usr/bin/yum'])

    def test_add_sudo_command_groups(self):
        self.master.run_command(['ipa', 'sudocmdgroup-add', 'readers',
                                 '--desc', '"Applications that read"'])

        self.master.run_command(['ipa', 'sudocmdgroup-add-member', 'readers',
                                 '--sudocmds', '/usr/bin/cat'])

        self.master.run_command(['ipa', 'sudocmdgroup-add-member', 'readers',
                                 '--sudocmds', '/usr/bin/tail'])

    def test_create_allow_all_rule(self):
        # Create rule that allows everything
        self.master.run_command(['ipa', 'sudorule-add',
                                 'testrule',
                                 '--usercat=all',
                                 '--hostcat=all',
                                 '--cmdcat=all',
                                 '--runasusercat=all',
                                 '--runasgroupcat=all'])

        # Add !authenticate option
        self.master.run_command(['ipa', 'sudorule-add-option',
                                 'testrule',
                                 '--sudooption', "!authenticate"])

    def test_add_sudo_rule(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

        result2 = self.list_sudo_commands("testuser2")
        assert "(ALL : ALL) NOPASSWD: ALL" in result2.stdout_text

    def test_sudo_rule_restricted_to_one_user_setup(self):
        # Configure the rule to not apply to anybody
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--usercat='])

        # Add the testuser1 to the rule
        self.master.run_command(['ipa', 'sudorule-add-user',
                                 'testrule',
                                 '--users', 'testuser1'])

    def test_sudo_rule_restricted_to_one_user(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

        result2 = self.list_sudo_commands("testuser2", raiseonerr=False)
        assert result2.returncode != 0

    def test_setting_category_to_all_with_valid_entries_user(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_user_teardown(self):
        # Remove the testuser1 from the rule
        self.master.run_command(['ipa', 'sudorule-remove-user',
                                 'testrule',
                                 '--users', 'testuser1'])

    def test_sudo_rule_restricted_to_one_group_setup(self):
        # Add the testgroup2 to the rule
        self.master.run_command(['ipa', 'sudorule-add-user',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_one_group(self):
        result1 = self.list_sudo_commands("testuser1", raiseonerr=False)
        assert result1.returncode != 0

        result2 = self.list_sudo_commands("testuser2")
        assert "(ALL : ALL) NOPASSWD: ALL" in result2.stdout_text

    def test_setting_category_to_all_with_valid_entries_user_group(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_group_teardown(self):
        # Remove the testgroup2 from the rule
        self.master.run_command(['ipa', 'sudorule-remove-user',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_one_host_negative_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

        # Configure the rule to not apply anywhere
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--hostcat='])

        # Add the master to the rule
        self.master.run_command(['ipa', 'sudorule-add-host',
                                 'testrule',
                                 '--hosts', self.master.hostname])

    def test_sudo_rule_restricted_to_one_host_negative(self):
        result1 = self.list_sudo_commands("testuser1", raiseonerr=False)
        assert result1.returncode != 0

    def test_sudo_rule_restricted_to_one_host_negative_teardown(self):
        # Remove the master from the rule
        self.master.run_command(['ipa', 'sudorule-remove-host',
                                 'testrule',
                                 '--hosts', self.master.hostname])

    def test_sudo_rule_restricted_to_one_host_setup(self):
        # Configure the rulle to not apply anywhere
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--hostcat='], raiseonerr=False)

        # Add the master to the rule
        self.master.run_command(['ipa', 'sudorule-add-host',
                                 'testrule',
                                 '--hosts', self.client.hostname])

    def test_sudo_rule_restricted_to_one_host(self):
        result1 = self.list_sudo_commands("testuser1", raiseonerr=False)
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_host(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_host_teardown(self):
        # Remove the master from the rule
        self.master.run_command(['ipa', 'sudorule-remove-host',
                                 'testrule',
                                 '--hosts', self.client.hostname])

    def test_sudo_rule_restricted_to_one_hostgroup_setup(self):
        # Add the testhostgroup to the rule
        self.master.run_command(['ipa', 'sudorule-add-host',
                                 'testrule',
                                 '--hostgroups', 'testhostgroup'])

    def test_sudo_rule_restricted_to_one_hostgroup(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_host_group(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_hostgroup_teardown(self):
        # Remove the testhostgroup from the rule
        self.master.run_command(['ipa', 'sudorule-remove-host',
                                 'testrule',
                                 '--hostgroups', 'testhostgroup'])

    def test_sudo_rule_restricted_to_one_hostmask_setup(self):
        # Add the client's /24 hostmask to the rule
        ip = self.client.ip
        self.master.run_command(['ipa', '-n', 'sudorule-add-host',
                                 'testrule',
                                 '--hostmask', '%s/24' % ip])

    def test_sudo_rule_restricted_to_one_hostmask(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: ALL" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_host_mask(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_one_hostmask_teardown(self):
        # Remove the client's /24 hostmask from the rule
        ip = self.client.ip
        self.master.run_command(['ipa', '-n', 'sudorule-remove-host',
                                 'testrule',
                                 '--hostmask', '%s/24' % ip])

    def test_sudo_rule_restricted_to_one_hostmask_negative_setup(self):
        # Add the master's hostmask to the rule
        ip = self.master.ip
        self.master.run_command(['ipa', '-n', 'sudorule-add-host',
                                 'testrule',
                                 '--hostmask', '%s/32' % ip])

    def test_sudo_rule_restricted_to_one_hostmask_negative(self):
        result1 = self.list_sudo_commands("testuser1")
        assert result1.returncode != 0

    def test_sudo_rule_restricted_to_one_hostmask_negative_teardown(self):
        # Remove the master's hostmask from the rule
        ip = self.master.ip
        self.master.run_command(['ipa', '-n', 'sudorule-remove-host',
                                 'testrule',
                                 '--hostmask', '%s/32' % ip])

    def test_sudo_rule_restricted_to_one_command_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

        # Configure the rule to not allow any command
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--cmdcat='])

        # Add the yum command to the rule
        self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'])

    def test_sudo_rule_restricted_to_one_command(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD: /usr/bin/yum" in result1.stdout_text

    def test_sudo_rule_restricted_to_command_and_command_group_setup(self):
        # Add the readers command group to the rule
        self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

    def test_sudo_rule_restricted_to_command_and_command_group(self):
        result1 = self.list_sudo_commands("testuser1")
        assert "(ALL : ALL) NOPASSWD:" in result1.stdout_text
        assert "/usr/bin/yum" in result1.stdout_text
        assert "/usr/bin/tail" in result1.stdout_text
        assert "/usr/bin/cat" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_command(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_command_and_command_group_teardown(self):
        # Remove the yum command from the rule
        self.master.run_command(['ipa', 'sudorule-remove-allow-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'])

        # Remove the readers command group from the rule
        self.master.run_command(['ipa', 'sudorule-remove-allow-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

    def test_sudo_rule_restricted_to_running_as_single_user_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

        # Configure the rule to not allow running commands as anybody
        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--runasusercat='])

        self.master.run_command(['ipa', 'sudorule-mod',
                                 'testrule',
                                 '--runasgroupcat='])

        # Allow running commands as testuser2
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--users', 'testuser2'])

    def test_sudo_rule_restricted_to_running_as_single_user(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: testuser2" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasuser(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_user_teardown(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--users', 'testuser2'])

    def test_sudo_rule_restricted_to_running_as_single_local_user_setup(self):
        # Allow running commands as testuser2
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--users', 'localuser'])

    def test_sudo_rule_restricted_to_running_as_single_local_user(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: localuser" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasuser_local(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_user_local_tear(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--users', 'localuser'])

    def test_sudo_rule_restricted_to_running_as_users_from_group_setup(self):
        # Allow running commands as users from testgroup2
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_running_as_users_from_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: %testgroup2" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasuser_group(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_users_from_group_teardown(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_run_as_users_from_local_group_setup(self):
        # Allow running commands as users from localgroup
        self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_sudo_rule_restricted_to_run_as_users_from_local_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: %localgroup" in result1.stdout_text
        assert "RunAsGroups:" not in result1.stdout_text

    def test_set_category_to_all_with_valid_entries_runasuser_group_local(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_run_as_users_from_local_group_tear(self):
        # Remove permission to run commands as testuser2
        self.master.run_command(['ipa', 'sudorule-remove-runasuser',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_sudo_rule_restricted_to_running_as_single_group_setup(self):
        # Allow running commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-add-runasgroup',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_running_as_single_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: root" in result1.stdout_text
        assert "RunAsGroups: testgroup2" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasgroup(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_group_teardown(self):
        # Remove permission to run commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-remove-runasgroup',
                                 'testrule',
                                 '--groups', 'testgroup2'])

    def test_sudo_rule_restricted_to_running_as_single_local_group_setup(self):
        # Allow running commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-add-runasgroup',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_sudo_rule_restricted_to_running_as_single_local_group(self):
        result1 = self.list_sudo_commands("testuser1", verbose=True)
        assert "RunAsUsers: root" in result1.stdout_text
        assert "RunAsGroups: localgroup" in result1.stdout_text

    def test_setting_category_to_all_with_valid_entries_runasgroup_local(self):
        result = self.reset_rule_categories(safe_delete=False)
        assert result.returncode != 0

    def test_sudo_rule_restricted_to_running_as_single_local_group_tear(self):
        # Remove permission to run commands as testgroup2
        self.master.run_command(['ipa', 'sudorule-remove-runasgroup',
                                 'testrule',
                                 '--groups', 'localgroup'])

    def test_category_all_validation_setup(self):
        # Reset testrule configuration
        self.reset_rule_categories()

    def test_category_all_validation_user(self):
        # Add the testuser1 to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-user',
                                          'testrule',
                                          '--users', 'testuser1'],
                                         raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_user_group(self):
        # Try to add the testgroup2 to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-user',
                                          'testrule',
                                          '--groups', 'testgroup2'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_user_local(self):
        # Try to add the local user to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-user',
                                          'testrule',
                                          '--users', 'localuser'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_host(self):
        # Try to add the master to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-host',
                                          'testrule',
                                          '--hosts', self.master.hostname],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_host_group(self):
        # Try to add the testhostgroup to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-host',
                                          'testrule',
                                          '--hostgroups', 'testhostgroup'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_host_mask(self):
        # Try to add the client's /24 hostmask to the rule
        ip = self.client.ip
        result = self.master.run_command(['ipa', '-n', 'sudorule-add-host',
                                          'testrule',
                                          '--hostmask', '%s/24' % ip],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_command_allow(self):
        # Try to add the yum command to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                          'testrule',
                                          '--sudocmds', '/usr/bin/yum'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_command_allow_group(self):
        # Try to add the readers command group to the rule
        result = self.master.run_command(['ipa', 'sudorule-add-allow-command',
                                          'testrule',
                                          '--sudocmdgroups', 'readers'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_command_deny(self):
        # Try to add the yum command to the rule
        # This SHOULD be allowed
        self.master.run_command(['ipa', 'sudorule-add-deny-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'],
                                 raiseonerr=False)

        self.master.run_command(['ipa', 'sudorule-remove-deny-command',
                                 'testrule',
                                 '--sudocmds', '/usr/bin/yum'],
                                 raiseonerr=False)

    def test_category_all_validation_command_deny_group(self):
        # Try to add the readers command group to the rule
        # This SHOULD be allowed
        self.master.run_command(['ipa', 'sudorule-add-deny-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

        self.master.run_command(['ipa', 'sudorule-remove-deny-command',
                                 'testrule',
                                 '--sudocmdgroups', 'readers'])

    def test_category_all_validation_runasuser(self):
        # Try to allow running commands as testuser2
        result = self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                          'testrule',
                                          '--users', 'testuser2'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_runasuser_group(self):
        # Try to allow running commands as users from testgroup2
        result = self.master.run_command(['ipa', 'sudorule-add-runasuser',
                                          'testrule',
                                          '--groups', 'testgroup2'],
                                          raiseonerr=False)
        assert result.returncode != 0

    def test_category_all_validation_runasgroup(self):
        # Try to allow running commands as testgroup2
        result = self.master.run_command(['ipa', 'sudorule-add-runasgroup',
                                          'testrule',
                                          '--groups', 'testgroup2'],
                                          raiseonerr=False)
        assert result.returncode != 0
