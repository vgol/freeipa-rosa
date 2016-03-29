# Authors: Rob Crittenden <rcritten@redhat.com>
#          David Kupka <dkupka@redhat.com>
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
#

# Some certmonger functions, mostly around updating the request file.
# This is used so we can add tracking to the Apache and 389-ds
# server certificates created during the IPA server installation.

import os
import sys
import time
import dbus
import shlex
from ipapython import ipautil
from ipapython import dogtag
from ipapython.ipa_log_manager import *
from ipaplatform.paths import paths
from ipaplatform import services

DBUS_CM_PATH = '/org/fedorahosted/certmonger'
DBUS_CM_IF = 'org.fedorahosted.certmonger'
DBUS_CM_REQUEST_IF = 'org.fedorahosted.certmonger.request'
DBUS_CM_CA_IF = 'org.fedorahosted.certmonger.ca'
DBUS_PROPERTY_IF = 'org.freedesktop.DBus.Properties'


class _cm_dbus_object(object):
    """
    Auxiliary class for convenient DBus object handling.
    """
    def __init__(self, bus, object_path, object_dbus_interface,
                 parent_dbus_interface=None, property_interface=False):
        """
        bus - DBus bus object, result of dbus.SystemBus() or dbus.SessionBus()
              Object is accesible over this DBus bus instance.
        object_path - path to requested object on DBus bus
        object_dbus_interface
        parent_dbus_interface
        property_interface - create DBus property interface? True or False
        """
        if bus is None or object_path is None or object_dbus_interface is None:
            raise RuntimeError(
                "bus, object_path and dbus_interface must not be None.")
        if parent_dbus_interface is None:
            parent_dbus_interface = object_dbus_interface
        self.bus = bus
        self.path = object_path
        self.obj_dbus_if = object_dbus_interface
        self.parent_dbus_if = parent_dbus_interface
        self.obj = bus.get_object(parent_dbus_interface, object_path)
        self.obj_if = dbus.Interface(self.obj, object_dbus_interface)
        if property_interface:
            self.prop_if = dbus.Interface(self.obj, DBUS_PROPERTY_IF)


def _start_certmonger():
    """
    Start certmonger daemon. If it's already running systemctl just ignores
    the command.
    """
    if not services.knownservices.certmonger.is_running():
        try:
            services.knownservices.certmonger.start()
        except Exception, e:
            root_logger.error('Failed to start certmonger: %s' % e)
            raise


def _connect_to_certmonger():
    """
    Start certmonger daemon and connect to it via DBus.
    """
    try:
        _start_certmonger()
    except (KeyboardInterrupt, OSError), e:
        root_logger.error('Failed to start certmonger: %s' % e)
        raise

    try:
        bus = dbus.SystemBus()
        cm = _cm_dbus_object(bus, DBUS_CM_PATH, DBUS_CM_IF)
    except dbus.DBusException, e:
        root_logger.error("Failed to access certmonger over DBus: %s", e)
        raise
    return cm


def _get_requests(criteria=dict()):
    """
    Get all requests that matches the provided criteria.
    """
    if not isinstance(criteria, dict):
        raise TypeError('"criteria" must be dict.')

    cm = _connect_to_certmonger()
    requests = []
    requests_paths = []
    if 'nickname' in criteria:
        request_path = cm.obj_if.find_request_by_nickname(criteria['nickname'])
        if request_path:
            requests_paths = [request_path]
    else:
        requests_paths = cm.obj_if.get_requests()

    for request_path in requests_paths:
        request = _cm_dbus_object(cm.bus, request_path, DBUS_CM_REQUEST_IF,
                                  DBUS_CM_IF, True)
        for criterion in criteria:
            if criterion == 'ca-name':
                ca_path = request.obj_if.get_ca()
                ca = _cm_dbus_object(cm.bus, ca_path, DBUS_CM_CA_IF,
                                     DBUS_CM_IF)
                value = ca.obj_if.get_nickname()
            else:
                value = request.prop_if.Get(DBUS_CM_REQUEST_IF, criterion)
            if value != criteria[criterion]:
                break
        else:
            requests.append(request)
    return requests


def _get_request(criteria):
    """
    Find request that matches criteria.
    If 'nickname' is specified other criteria are ignored because 'nickname'
    uniquely identify single request.
    When multiple or none request matches specified criteria RuntimeError is
    raised.
    """
    requests = _get_requests(criteria)
    if len(requests) == 0:
        return None
    elif len(requests) == 1:
        return requests[0]
    else:
        raise RuntimeError("Criteria expected to be met by 1 request, got %s."
                           % len(requests))


def get_request_value(request_id, directive):
    """
    Get property of request.
    """
    try:
        request = _get_request(dict(nickname=request_id))
    except RuntimeError, e:
        root_logger.error('Failed to get request: %s' % e)
        raise
    if request:
        if directive == 'ca-name':
            ca_path = request.obj_if.get_ca()
            ca = _cm_dbus_object(request.bus, ca_path, DBUS_CM_CA_IF,
                                 DBUS_CM_IF)
            return ca.obj_if.get_nickname()
        else:
            return request.prop_if.Get(DBUS_CM_REQUEST_IF, directive)
    else:
        return None


def get_request_id(criteria):
    """
    If you don't know the certmonger request_id then try to find it by looking
    through all the requests.

    criteria is a tuple of key/value to search for. The more specific
    the better. An error is raised if multiple request_ids are returned for
    the same criteria.

    None is returned if none of the criteria match.
    """
    try:
        request = _get_request(criteria)
    except RuntimeError, e:
        root_logger.error('Failed to get request: %s' % e)
        raise
    if request:
        return request.prop_if.Get(DBUS_CM_REQUEST_IF, 'nickname')
    else:
        return None


def get_requests_for_dir(dir):
    """
    Return a list containing the request ids for a given NSS database
    directory.
    """
    reqid = []
    criteria = {'cert-storage': 'NSSDB', 'key-storage': 'NSSDB',
                'cert-database': dir, 'key-database': dir, }
    requests = _get_requests(criteria)
    for request in requests:
        reqid.append(request.prop_if.Get(DBUS_CM_REQUEST_IF, 'nickname'))

    return reqid


def add_request_value(request_id, directive, value):
    """
    Add a new directive to a certmonger request file.
    """
    try:
        request = _get_request({'nickname': request_id})
    except RuntimeError, e:
        root_logger.error('Failed to get request: %s' % e)
        raise
    if request:
        request.obj_if.modify({directive: value})


def add_principal(request_id, principal):
    """
    In order for a certmonger request to be renewable it needs a principal.

    When an existing certificate is added via start-tracking it won't have
    a principal.
    """
    add_request_value(request_id, 'template-principal', [principal])


def add_subject(request_id, subject):
    """
    In order for a certmonger request to be renwable it needs the subject
    set in the request file.

    When an existing certificate is added via start-tracking it won't have
    a subject_template set.
    """
    add_request_value(request_id, 'template-subject', subject)


def request_cert(nssdb, nickname, subject, principal, passwd_fname=None):
    """
    Execute certmonger to request a server certificate.
    """
    cm = _connect_to_certmonger()
    ca_path = cm.obj_if.find_ca_by_nickname('IPA')
    if not ca_path:
        raise RuntimeError('IPA CA not found')
    request_parameters = dict(KEY_STORAGE='NSSDB', CERT_STORAGE='NSSDB',
                              CERT_LOCATION=nssdb, CERT_NICKNAME=nickname,
                              KEY_LOCATION=nssdb, KEY_NICKNAME=nickname,
                              SUBJECT=subject, PRINCIPAL=[principal],
                              CA=ca_path)
    if passwd_fname:
        request_parameters['KEY_PIN_FILE'] = passwd_fname
    result = cm.obj_if.add_request(request_parameters)
    try:
        if result[0]:
            request = _cm_dbus_object(cm.bus, result[1], DBUS_CM_REQUEST_IF,
                                      DBUS_CM_IF, True)
    except TypeError:
        root_logger.error('Failed to get create new request.')
        raise
    return request.obj_if.get_nickname()


def start_tracking(nickname, secdir, password_file=None, command=None):
    """
    Tell certmonger to track the given certificate nickname in NSS
    database in secdir protected by optional password file password_file.

    command is an optional parameter which specifies a command for
    certmonger to run when it renews a certificate. This command must
    reside in /usr/lib/ipa/certmonger to work with SELinux.

    Returns certificate nickname.
    """
    cm = _connect_to_certmonger()
    params = {'TRACK': True}
    params['cert-nickname'] = nickname
    params['cert-database'] = os.path.abspath(secdir)
    params['cert-storage'] = 'NSSDB'
    params['key-nickname'] = nickname
    params['key-database'] = os.path.abspath(secdir)
    params['key-storage'] = 'NSSDB'
    ca_path = cm.obj_if.find_ca_by_nickname('IPA')
    if not ca_path:
        raise RuntimeError('IPA CA not found')
    params['ca'] = ca_path
    if command:
        params['cert-postsave-command'] = command
    if password_file:
        params['KEY_PIN_FILE'] = os.path.abspath(password_file)
    result = cm.obj_if.add_request(params)
    try:
        if result[0]:
            request = _cm_dbus_object(cm.bus, result[1], DBUS_CM_REQUEST_IF,
                                      DBUS_CM_IF, True)
    except TypeError, e:
        root_logger.error('Failed to add new request.')
        raise
    return request.prop_if.Get(DBUS_CM_REQUEST_IF, 'nickname')


def stop_tracking(secdir, request_id=None, nickname=None):
    """
    Stop tracking the current request using either the request_id or nickname.

    Returns True or False
    """
    if request_id is None and nickname is None:
        raise RuntimeError('Both request_id and nickname are missing.')

    criteria = {'cert-database': secdir}
    if request_id:
        criteria['nickname'] = request_id
    if nickname:
        criteria['cert-nickname'] = nickname
    try:
        request = _get_request(criteria)
    except RuntimeError, e:
        root_logger.error('Failed to get request: %s' % e)
        raise
    if request:
        cm = _connect_to_certmonger()
        cm.obj_if.remove_request(request.path)


def modify(request_id, profile=None):
    if profile:
        request = _get_request({'nickname': request_id})
        if request:
            request.obj_if.modify({'template-profile': profile})


def resubmit_request(request_id, profile=None):
    request = _get_request({'nickname': request_id})
    if request:
        if profile:
            request.obj_if.modify({'template-profile': profile})
        request.obj_if.resubmit()


def _find_IPA_ca():
    """
    Look through all the certmonger CA files to find the one that
    has id=IPA

    We can use find_request_value because the ca files have the
    same file format.
    """
    cm = _connect_to_certmonger()
    ca_path = cm.obj_if.find_ca_by_nickname('IPA')
    return _cm_dbus_object(cm.bus, ca_path, DBUS_CM_CA_IF, DBUS_CM_IF, True)


def add_principal_to_cas(principal):
    """
    If the hostname we were passed to use in ipa-client-install doesn't
    match the value of gethostname() then we need to append
    -k host/HOSTNAME@REALM to the ca helper defined for
    /usr/libexec/certmonger/ipa-submit.

    We also need to restore this on uninstall.
    """
    ca = _find_IPA_ca()
    if ca:
        ext_helper = ca.prop_if.Get(DBUS_CM_CA_IF, 'external-helper')
        if ext_helper and '-k' not in shlex.split(ext_helper):
            ext_helper = '%s -k %s' % (ext_helper.strip(), principal)
            ca.prop_if.Set(DBUS_CM_CA_IF, 'external-helper', ext_helper)


def remove_principal_from_cas():
    """
    Remove any -k principal options from the ipa_submit helper.
    """
    ca = _find_IPA_ca()
    if ca:
        ext_helper = ca.prop_if.Get(DBUS_CM_CA_IF, 'external-helper')
        if ext_helper and '-k' in shlex.split(ext_helper):
            ext_helper = shlex.split(ext_helper)[0]
            ca.prop_if.Set(DBUS_CM_CA_IF, 'external-helper', ext_helper)


def get_pin(token, dogtag_constants=None):
    """
    Dogtag stores its NSS pin in a file formatted as token:PIN.

    The caller is expected to handle any exceptions raised.
    """
    if dogtag_constants is None:
        dogtag_constants = dogtag.configured_constants()
    with open(dogtag_constants.PASSWORD_CONF_PATH, 'r') as f:
        for line in f:
            (tok, pin) = line.split('=', 1)
            if token == tok:
                return pin.strip()
    return None


def dogtag_start_tracking(ca, nickname, pin, pinfile, secdir, pre_command,
                          post_command, profile=None):
    """
    Tell certmonger to start tracking a dogtag CA certificate. These
    are handled differently because their renewal must be done directly
    and not through IPA.

    This uses the generic certmonger command getcert so we can specify
    a different helper.

    pre_command is the script to execute before a renewal is done.
    post_command is the script to execute after a renewal is done.

    Both commands can be None.
    """

    cm = _connect_to_certmonger()
    certmonger_cmd_template = paths.CERTMONGER_COMMAND_TEMPLATE

    params = {'TRACK': True}
    params['cert-nickname'] = nickname
    params['cert-database'] = os.path.abspath(secdir)
    params['cert-storage'] = 'NSSDB'
    params['key-nickname'] = nickname
    params['key-database'] = os.path.abspath(secdir)
    params['key-storage'] = 'NSSDB'
    ca_path = cm.obj_if.find_ca_by_nickname(ca)
    if ca_path:
        params['ca'] = ca_path
    if pin:
        params['KEY_PIN'] = pin
    if pinfile:
        params['KEY_PIN_FILE'] = os.path.abspath(pinfile)
    if pre_command:
        if not os.path.isabs(pre_command):
            if sys.maxsize > 2**32L:
                libpath = 'lib64'
            else:
                libpath = 'lib'
            pre_command = certmonger_cmd_template % (libpath, pre_command)
        params['cert-presave-command'] = pre_command
    if post_command:
        if not os.path.isabs(post_command):
            if sys.maxsize > 2**32L:
                libpath = 'lib64'
            else:
                libpath = 'lib'
            post_command = certmonger_cmd_template % (libpath, post_command)
        params['cert-postsave-command'] = post_command
    if profile:
        params['ca-profile'] = profile

    cm.obj_if.add_request(params)


def check_state(dirs):
    """
    Given a set of directories and nicknames verify that we are no longer
    tracking certificates.

    dirs is a list of directories to test for. We will return a tuple
    of nicknames for any tracked certificates found.

    This can only check for NSS-based certificates.
    """
    reqids = []
    for dir in dirs:
        reqids.extend(get_requests_for_dir(dir))

    return reqids


def wait_for_request(request_id, timeout=120):
    for i in range(0, timeout, 5):
        state = get_request_value(request_id, 'status')
        root_logger.debug("certmonger request is in state %r", state)
        if state in ('CA_REJECTED', 'CA_UNREACHABLE', 'CA_UNCONFIGURED',
                     'NEED_GUIDANCE', 'NEED_CA', 'MONITORING'):
            break
        time.sleep(5)
    else:
        raise RuntimeError("request timed out")

    return state

if __name__ == '__main__':
    request_id = request_cert(paths.HTTPD_ALIAS_DIR, "Test",
                              "cn=tiger.example.com,O=IPA",
                              "HTTP/tiger.example.com@EXAMPLE.COM")
    csr = get_request_value(request_id, 'csr')
    print csr
    stop_tracking(request_id)
