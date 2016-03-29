# Author: Alexander Bokovoy <abokovoy@redhat.com>
#         Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2011-2014   Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Contains Red Hat OS family-specific service class implementations.
"""

import os
import time
import xml.dom.minidom
import contextlib

from ipaplatform.tasks import tasks
from ipaplatform.base import services as base_services

from ipapython import ipautil, dogtag
from ipapython.ipa_log_manager import root_logger
from ipalib import api
from ipaplatform.paths import paths

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names

# For beginning just remap names to add .service
# As more services will migrate to systemd, unit names will deviate and
# mapping will be kept in this dictionary
redhat_system_units = dict((x, "%s.service" % x)
                           for x in base_services.wellknownservices)

redhat_system_units['rpcgssd'] = 'nfs-secure.service'
redhat_system_units['rpcidmapd'] = 'nfs-idmap.service'

# Rewrite dirsrv and pki-tomcatd services as they support instances via separate
# service generator. To make this working, one needs to have both foo@.servic
# and foo.target -- the latter is used when request should be coming for
# all instances (like stop). systemd, unfortunately, does not allow one
# to request action for all service instances at once if only foo@.service
# unit is available. To add more, if any of those services need to be
# started/stopped automagically, one needs to manually create symlinks in
# /etc/systemd/system/foo.target.wants/ (look into systemd.py's enable()
# code).

redhat_system_units['dirsrv'] = 'dirsrv@.service'
# Our directory server instance for PKI is dirsrv@PKI-IPA.service
redhat_system_units['pkids'] = 'dirsrv@PKI-IPA.service'
# Old style PKI instance
redhat_system_units['pki-cad'] = 'pki-cad@pki-ca.service'
redhat_system_units['pki_cad'] = redhat_system_units['pki-cad']
# Our PKI instance is pki-tomcatd@pki-tomcat.service
redhat_system_units['pki-tomcatd'] = 'pki-tomcatd@pki-tomcat.service'
redhat_system_units['pki_tomcatd'] = redhat_system_units['pki-tomcatd']
redhat_system_units['ipa-otpd'] = 'ipa-otpd.socket'
redhat_system_units['ipa-dnskeysyncd'] = 'ipa-dnskeysyncd.service'
redhat_system_units['named-regular'] = 'named.service'
redhat_system_units['named-pkcs11'] = 'named-pkcs11.service'
redhat_system_units['named'] = redhat_system_units['named-pkcs11']
redhat_system_units['ods-enforcerd'] = 'ods-enforcerd.service'
redhat_system_units['ods_enforcerd'] = redhat_system_units['ods-enforcerd']
redhat_system_units['ods-signerd'] = 'ods-signerd.service'
redhat_system_units['ods_signerd'] = redhat_system_units['ods-signerd']


# Service classes that implement Red Hat OS family-specific behaviour

class RedHatService(base_services.SystemdService):
    system_units = redhat_system_units

    def __init__(self, service_name):
        systemd_name = service_name
        if service_name in self.system_units:
            systemd_name = self.system_units[service_name]
        else:
            if '.' not in service_name:
                # if service_name does not have a dot, it is not foo.service
                # and not a foo.target. Thus, not correct service name for
                # systemd, default to foo.service style then
                systemd_name = "%s.service" % (service_name)
        super(RedHatService, self).__init__(service_name, systemd_name)


class RedHatDirectoryService(RedHatService):

    def tune_nofile_platform(self, num=8192, fstore=None):
        """
        Increase the number of files descriptors available to directory server
        from the default 1024 to 8192. This will allow to support a greater
        number of clients out of the box.

        This is a part of the implementation that is systemd-specific.

        Returns False if the setting of the nofile limit needs to be skipped.
        """

        if os.path.exists(paths.SYSCONFIG_DIRSRV_SYSTEMD):
            # We need to enable LimitNOFILE=8192 in the dirsrv@.service
            # Since 389-ds-base-1.2.10-0.8.a7 the configuration of the
            # service parameters is performed via
            # /etc/sysconfig/dirsrv.systemd file which is imported by systemd
            # into dirsrv@.service unit

            replacevars = {'LimitNOFILE': str(num)}
            ipautil.inifile_replace_variables(paths.SYSCONFIG_DIRSRV_SYSTEMD,
                                              'service',
                                              replacevars=replacevars)
            tasks.restore_context(paths.SYSCONFIG_DIRSRV_SYSTEMD)
            ipautil.run(["/bin/systemctl", "--system", "daemon-reload"],
                        raiseonerr=False)

        return True

    def restart(self, instance_name="", capture_output=True, wait=True,
                ldapi=False):
    # We need to explicitly enable instances to install proper symlinks as
    # dirsrv.target.wants/ dependencies. Standard systemd service class does it
    # on enable() method call. Unfortunately, ipa-server-install does not do
    # explicit dirsrv.enable() because the service startup is handled by ipactl.
    #
    # If we wouldn't do this, our instances will not be started as systemd would
    # not have any clue about instances (PKI-IPA and the domain we serve)
    # at all. Thus, hook into dirsrv.restart().

        if instance_name:
            elements = self.systemd_name.split("@")

            srv_etc = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.systemd_name)
            srv_tgt = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.SYSTEMD_SRV_TARGET % (elements[0]))
            srv_lnk = os.path.join(srv_tgt,
                                   self.service_instance(instance_name))

            if not os.path.exists(srv_etc):
                self.enable(instance_name)
            elif not os.path.samefile(srv_etc, srv_lnk):
                os.unlink(srv_lnk)
                os.symlink(srv_etc, srv_lnk)

        with self.__wait(instance_name, wait, ldapi) as wait:
            super(RedHatDirectoryService, self).restart(
                instance_name, capture_output=capture_output, wait=wait)

    def start(self, instance_name="", capture_output=True, wait=True,
              ldapi=False):
        with self.__wait(instance_name, wait, ldapi) as wait:
            super(RedHatDirectoryService, self).start(
                instance_name, capture_output=capture_output, wait=wait)

    @contextlib.contextmanager
    def __wait(self, instance_name, wait, ldapi):
        if ldapi:
            instance_name = self.service_instance(instance_name)
            if instance_name.endswith('.service'):
                instance_name = instance_name[:-8]
            if instance_name.startswith('dirsrv'):
                # this is intentional, return the empty string if the instance
                # name is 'dirsrv'
                instance_name = instance_name[7:]
            if not instance_name:
                ldapi = False
        if ldapi:
            yield False
            socket_name = paths.SLAPD_INSTANCE_SOCKET_TEMPLATE % instance_name
            ipautil.wait_for_open_socket(socket_name,
                                         self.api.env.startup_timeout)
        else:
            yield wait


class RedHatIPAService(RedHatService):
    # Enforce restart of IPA services when we do enable it
    # This gets around the fact that after ipa-server-install systemd thinks
    # ipa.service is not yet started but all services were actually started
    # already.
    def enable(self, instance_name=""):
        super(RedHatIPAService, self).enable(instance_name)
        self.restart(instance_name)


class RedHatSSHService(RedHatService):
    def get_config_dir(self, instance_name=""):
        return '/etc/ssh'


class RedHatCAService(RedHatService):
    def wait_until_running(self):
        root_logger.debug('Waiting until the CA is running')
        timeout = float(api.env.startup_timeout)
        op_timeout = time.time() + timeout
        while time.time() < op_timeout:
            try:
                # FIXME https://fedorahosted.org/freeipa/ticket/4716
                # workaround
                #
                # status = dogtag.ca_status(use_proxy=use_proxy)
                #
                port = 8443

                url = "https://%(host_port)s%(path)s" % {
                    "host_port": ipautil.format_netloc(api.env.ca_host, port),
                    "path": "/ca/admin/ca/getStatus"
                }

                args = [
                    paths.BIN_WGET,
                    '-S', '-O', '-',
                    '--timeout=30',
                    '--no-check-certificate',
                    url
                ]

                stdout, stderr, returncode = ipautil.run(args)

                status = dogtag._parse_ca_status(stdout)
                # end of workaround
            except Exception as e:
                status = 'check interrupted due to error: %s' % e
            root_logger.debug('The CA status is: %s' % status)
            if status == 'running':
                break
            root_logger.debug('Waiting for CA to start...')
            time.sleep(1)
        else:
            raise RuntimeError('CA did not start in %ss' % timeout)

    def start(self, instance_name="", capture_output=True, wait=True):
        super(RedHatCAService, self).start(
            instance_name, capture_output=capture_output, wait=wait)
        if wait:
            self.wait_until_running()

    def restart(self, instance_name="", capture_output=True, wait=True):
        super(RedHatCAService, self).restart(
            instance_name, capture_output=capture_output, wait=wait)
        if wait:
            self.wait_until_running()


class RedHatNamedService(RedHatService):
    def get_user_name(self):
        return u'named'

    def get_group_name(self):
        return u'named'

    def get_binary_path(self):
        return paths.NAMED_PKCS11

    def get_package_name(self):
        return u"bind-pkcs11"


class RedHatODSEnforcerdService(RedHatService):
    def get_user_name(self):
        return u'ods'

    def get_group_name(self):
        return u'ods'


# Function that constructs proper Red Hat OS family-specific server classes for
# services of specified name

def redhat_service_class_factory(name):
    if name == 'dirsrv':
        return RedHatDirectoryService(name)
    if name == 'ipa':
        return RedHatIPAService(name)
    if name == 'sshd':
        return RedHatSSHService(name)
    if name in ('pki-cad', 'pki_cad', 'pki-tomcatd', 'pki_tomcatd'):
        return RedHatCAService(name)
    if name == 'named':
        return RedHatNamedService(name)
    if name in ('ods-enforcerd', 'ods_enforcerd'):
        return RedHatODSEnforcerdService(name)
    return RedHatService(name)


# Magicdict containing RedHatService instances.

class RedHatServices(base_services.KnownServices):
    def service_class_factory(self, name):
        return redhat_service_class_factory(name)

    def __init__(self):
        services = dict()
        for s in base_services.wellknownservices:
            services[s] = self.service_class_factory(s)
        # Call base class constructor. This will lock services to read-only
        super(RedHatServices, self).__init__(services)


# Objects below are expected to be exported by platform module

from ipaplatform.base.services import timedate_services
service = redhat_service_class_factory
knownservices = RedHatServices()
