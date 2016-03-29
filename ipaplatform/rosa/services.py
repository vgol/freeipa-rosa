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
Contains ROSA-specific service class implementations.
"""

from ipaplatform.redhat import services as redhat_services

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names
rosa_system_units = redhat_services.redhat_system_units

# Service that sets domainname on ROSA is called fedora-domainname.service
rosa_system_units['domainname'] = 'fedora-domainname.service'

# The messagebus service on ROSA is dbus.
rosa_system_units['messagebus'] = 'dbus.service'


# Service classes that implement ROSA-specific behaviour
class RosaService(redhat_services.RedHatService):
    system_units = rosa_system_units


# Function that constructs proper Fedora-specific server classes for services
# of specified name

def rosa_service_class_factory(name):
    if name == 'domainname':
        return RosaService(name)
    return redhat_services.redhat_service_class_factory(name)


# Magicdict containing FedoraService instances.

class RosaServices(redhat_services.RedHatServices):
    def service_class_factory(self, name):
        return rosa_service_class_factory(name)


# Objects below are expected to be exported by platform module

from ipaplatform.base.services import timedate_services
service = rosa_service_class_factory
knownservices = RosaServices()
