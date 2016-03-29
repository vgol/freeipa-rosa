# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Martin Kosek <mkosek@redhat.com>
#          Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
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

'''
This module contains default Red Hat OS family-specific implementations of
system tasks.
'''

import os
import stat
import socket
import sys
import urllib
import base64

from subprocess import CalledProcessError
from nss.error import NSPRError
from pyasn1.error import PyAsn1Error

from ipapython.ipa_log_manager import root_logger, log_mgr
from ipapython import ipautil
import ipapython.errors

from ipalib import x509 # FIXME: do not import from ipalib

from ipaplatform.paths import paths
from ipaplatform.redhat.authconfig import RedHatAuthConfig
from ipaplatform.base.tasks import BaseTaskNamespace


log = log_mgr.get_logger(__name__)


def selinux_enabled():
    """
    Check if SELinux is enabled.
    """
    if os.path.exists(paths.SELINUXENABLED):
        try:
            ipautil.run([paths.SELINUXENABLED])
            return True
        except ipautil.CalledProcessError:
            # selinuxenabled returns 1 if not enabled
            return False
    else:
        # No selinuxenabled, no SELinux
        return False


class RedHatTaskNamespace(BaseTaskNamespace):

    def restore_context(self, filepath, restorecon=paths.SBIN_RESTORECON):
        """
        restore security context on the file path
        SELinux equivalent is /path/to/restorecon <filepath>
        restorecon's return values are not reliable so we have to
        ignore them (BZ #739604).

        ipautil.run() will do the logging.
        """

        if not selinux_enabled():
            return

        if (os.path.exists(restorecon)):
            ipautil.run([restorecon, filepath], raiseonerr=False)

    def check_selinux_status(self, restorecon=paths.RESTORECON):
        """
        We don't have a specific package requirement for policycoreutils
        which provides restorecon. This is because we don't require
        SELinux on client installs. However if SELinux is enabled then
        this package is required.

        This function returns nothing but may raise a Runtime exception
        if SELinux is enabled but restorecon is not available.
        """
        if not selinux_enabled():
            return

        if not os.path.exists(restorecon):
            raise RuntimeError('SELinux is enabled but %s does not exist.\n'
                               'Install the policycoreutils package and start '
                               'the installation again.' % restorecon)

    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):

        auth_config = RedHatAuthConfig()
        if statestore.has_state('authconfig'):
            # disable only those configurations that we enabled during install
            for conf in ('ldap', 'krb5', 'sssd', 'sssdauth', 'mkhomedir'):
                cnf = statestore.restore_state('authconfig', conf)
                # Do not disable sssd, as this can cause issues with its later
                # uses. Remove it from statestore however, so that it becomes
                # empty at the end of uninstall process.
                if cnf and conf != 'sssd':
                    auth_config.disable(conf)
        else:
            # There was no authconfig status store
            # It means the code was upgraded after original install
            # Fall back to old logic
            auth_config.disable("ldap")
            auth_config.disable("krb5")
            if not(was_sssd_installed and was_sssd_configured):
                # Only disable sssdauth. Disabling sssd would cause issues
                # with its later uses.
                auth_config.disable("sssdauth")
            auth_config.disable("mkhomedir")

        auth_config.execute()

    def set_nisdomain(self, nisdomain):
        # Let authconfig setup the permanent configuration
        auth_config = RedHatAuthConfig()
        auth_config.add_parameter("nisdomain", nisdomain)
        auth_config.execute()

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore):
        auth_config = RedHatAuthConfig()

        if sssd:
            statestore.backup_state('authconfig', 'sssd', True)
            statestore.backup_state('authconfig', 'sssdauth', True)
            auth_config.enable("sssd")
            auth_config.enable("sssdauth")
        else:
            statestore.backup_state('authconfig', 'ldap', True)
            auth_config.enable("ldap")
            auth_config.enable("forcelegacy")

        if mkhomedir:
            statestore.backup_state('authconfig', 'mkhomedir', True)
            auth_config.enable("mkhomedir")

        auth_config.execute()

    def modify_pam_to_use_krb5(self, statestore):
        auth_config = RedHatAuthConfig()
        statestore.backup_state('authconfig', 'krb5', True)
        auth_config.enable("krb5")
        auth_config.add_option("nostart")
        auth_config.execute()

    def reload_systemwide_ca_store(self):
        try:
            ipautil.run([paths.UPDATE_CA_TRUST])
        except CalledProcessError, e:
            root_logger.error(
                "Could not update systemwide CA trust database: %s", e)
            return False
        else:
            root_logger.info("Systemwide CA database updated.")
            return True

    def insert_ca_certs_into_systemwide_ca_store(self, ca_certs):
        new_cacert_path = paths.SYSTEMWIDE_IPA_CA_CRT

        if os.path.exists(new_cacert_path):
            try:
                os.remove(new_cacert_path)
            except OSError, e:
                root_logger.error(
                    "Could not remove %s: %s", new_cacert_path, e)
                return False

        new_cacert_path = paths.IPA_P11_KIT

        try:
            f = open(new_cacert_path, 'w')
        except IOError, e:
            root_logger.info("Failed to open %s: %s" % (new_cacert_path, e))
            return False

        f.write("# This file was created by IPA. Do not edit.\n"
                "\n")

        has_eku = set()
        for cert, nickname, trusted, ext_key_usage in ca_certs:
            try:
                subject = x509.get_der_subject(cert, x509.DER)
                issuer = x509.get_der_issuer(cert, x509.DER)
                serial_number = x509.get_der_serial_number(cert, x509.DER)
                public_key_info = x509.get_der_public_key_info(cert, x509.DER)
            except (NSPRError, PyAsn1Error), e:
                root_logger.warning(
                    "Failed to decode certificate \"%s\": %s", nickname, e)
                continue

            label = urllib.quote(nickname)
            subject = urllib.quote(subject)
            issuer = urllib.quote(issuer)
            serial_number = urllib.quote(serial_number)
            public_key_info = urllib.quote(public_key_info)

            cert = base64.b64encode(cert)
            cert = x509.make_pem(cert)

            obj = ("[p11-kit-object-v1]\n"
                   "class: certificate\n"
                   "certificate-type: x-509\n"
                   "certificate-category: authority\n"
                   "label: \"%(label)s\"\n"
                   "subject: \"%(subject)s\"\n"
                   "issuer: \"%(issuer)s\"\n"
                   "serial-number: \"%(serial_number)s\"\n"
                   "x-public-key-info: \"%(public_key_info)s\"\n" %
                   dict(label=label,
                        subject=subject,
                        issuer=issuer,
                        serial_number=serial_number,
                        public_key_info=public_key_info))
            if trusted is True:
                obj += "trusted: true\n"
            elif trusted is False:
                obj += "x-distrusted: true\n"
            obj += "%s\n\n" % cert
            f.write(obj)

            if ext_key_usage is not None and public_key_info not in has_eku:
                if not ext_key_usage:
                    ext_key_usage = {x509.EKU_PLACEHOLDER}
                try:
                    ext_key_usage = x509.encode_ext_key_usage(ext_key_usage)
                except PyAsn1Error, e:
                    root_logger.warning(
                        "Failed to encode extended key usage for \"%s\": %s",
                        nickname, e)
                    continue
                value = urllib.quote(ext_key_usage)
                obj = ("[p11-kit-object-v1]\n"
                       "class: x-certificate-extension\n"
                       "label: \"ExtendedKeyUsage for %(label)s\"\n"
                       "x-public-key-info: \"%(public_key_info)s\"\n"
                       "object-id: 2.5.29.37\n"
                       "value: \"%(value)s\"\n\n" %
                       dict(label=label,
                            public_key_info=public_key_info,
                            value=value))
                f.write(obj)
                has_eku.add(public_key_info)

        f.close()

        # Add the CA to the systemwide CA trust database
        if not self.reload_systemwide_ca_store():
            return False

        return True

    def remove_ca_certs_from_systemwide_ca_store(self):
        result = True
        update = False

        # Remove CA cert from systemwide store
        for new_cacert_path in (paths.IPA_P11_KIT,
                                paths.SYSTEMWIDE_IPA_CA_CRT):
            if not os.path.exists(new_cacert_path):
                continue
            try:
                os.remove(new_cacert_path)
            except OSError, e:
                root_logger.error(
                    "Could not remove %s: %s", new_cacert_path, e)
                result = False
            else:
                update = True

        if update:
            if not self.reload_systemwide_ca_store():
                return False

        return result

    def backup_and_replace_hostname(self, fstore, statestore, hostname):
        old_hostname = socket.gethostname()
        try:
            ipautil.run([paths.BIN_HOSTNAME, hostname])
        except ipautil.CalledProcessError, e:
            print >>sys.stderr, ("Failed to set this machine hostname to "
                                 "%s (%s)." % (hostname, str(e)))

        filepath = paths.ETC_HOSTNAME
        if os.path.exists(filepath):
            # read old hostname
            with open(filepath, 'r') as f:
                for line in f.readlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        # skip comment or empty line
                        continue
                    old_hostname = line
                    break
            fstore.backup_file(filepath)

        with open(filepath, 'w') as f:
            f.write("%s\n" % hostname)
        os.chmod(filepath,
                 stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        os.chown(filepath, 0, 0)
        self.restore_context(filepath)

        # store old hostname
        statestore.backup_state('network', 'hostname', old_hostname)

    def restore_network_configuration(self, fstore, statestore):
        old_filepath = paths.SYSCONFIG_NETWORK
        old_hostname = statestore.get_state('network', 'hostname')
        hostname_was_configured = False

        if fstore.has_file(old_filepath):
            # This is Fedora >=18 instance that was upgraded from previous
            # Fedora version which held network configuration
            # in /etc/sysconfig/network
            old_filepath_restore = paths.SYSCONFIG_NETWORK_IPABKP
            fstore.restore_file(old_filepath, old_filepath_restore)
            print "Deprecated configuration file '%s' was restored to '%s'" \
                    % (old_filepath, old_filepath_restore)
            hostname_was_configured = True

        filepath = paths.ETC_HOSTNAME
        if fstore.has_file(filepath):
            fstore.restore_file(filepath)
            hostname_was_configured = True

        if not hostname_was_configured and old_hostname:
            # hostname was not configured before but was set by IPA. Delete
            # /etc/hostname to restore previous configuration
            try:
                os.remove(filepath)
            except OSError:
                pass

    def set_selinux_booleans(self, required_settings, backup_func=None):
        def get_setsebool_args(changes):
            args = [paths.SETSEBOOL, "-P"]
            args.extend(["%s=%s" % update for update in changes.iteritems()])

            return args

        if not selinux_enabled():
            return False

        updated_vars = {}
        failed_vars = {}
        for setting, state in required_settings.iteritems():
            if state is None:
                continue
            try:
                (stdout, stderr, rc) = ipautil.run([paths.GETSEBOOL, setting])
                original_state = stdout.split()[2]
                if backup_func is not None:
                    backup_func(setting, original_state)

                if original_state != state:
                    updated_vars[setting] = state
            except ipautil.CalledProcessError, e:
                log.error("Cannot get SELinux boolean '%s': %s", setting, e)
                failed_vars[setting] = state

        if updated_vars:
            args = get_setsebool_args(updated_vars)
            try:
                ipautil.run(args)
            except ipautil.CalledProcessError:
                failed_vars.update(updated_vars)

        if failed_vars:
            raise ipapython.errors.SetseboolError(
                failed=failed_vars,
                command=' '.join(get_setsebool_args(failed_vars)))

        return True

    def create_system_user(self, name, group, homedir, shell, uid = None, gid = None, comment = None):
        """
        Create a system user with a corresponding group

        According to https://fedoraproject.org/wiki/Packaging:UsersAndGroups?rd=Packaging/UsersAndGroups#Soft_static_allocation
        some system users should have fixed UID, GID and other parameters set.
        This values should be constant and may be hardcoded.
        Add other values for other users when needed.
        """
        if name == 'pkiuser':
            if uid is None:
                uid = 17
            if gid is None:
                gid = 17
            if comment is None:
                comment = 'CA System User'
        if name == 'dirsrv':
            if comment is None:
                comment = 'DS System User'

        super(RedHatTaskNamespace, self).create_system_user(name, group,
            homedir, shell, uid, gid, comment)


tasks = RedHatTaskNamespace()
