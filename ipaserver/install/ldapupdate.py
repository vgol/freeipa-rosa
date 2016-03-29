# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

# Documentation can be found at http://freeipa.org/page/LdapUpdate

# TODO
# save undo files?

import base64
import sys
import uuid
import platform
import time
import os
import pwd
import fnmatch
import re

import krbV
import ldap

from ipaserver.install import installutils
from ipapython import ipautil, ipaldap
from ipalib import errors
from ipalib import api, create_api
from ipalib import constants
from ipaplatform.paths import paths
from ipaplatform import services
from ipapython.dn import DN
from ipapython.ipa_log_manager import *
from ipapython.ipautil import wait_for_open_socket

UPDATES_DIR=paths.UPDATES_DIR


def connect(ldapi=False, realm=None, fqdn=None, dm_password=None, pw_name=None):
    """Create a connection for updates"""
    if ldapi:
        conn = ipaldap.IPAdmin(ldapi=True, realm=realm, decode_attrs=False)
    else:
        conn = ipaldap.IPAdmin(fqdn, ldapi=False, realm=realm, decode_attrs=False)
    try:
        if dm_password:
            conn.do_simple_bind(binddn=DN(('cn', 'directory manager')),
                                bindpw=dm_password)
        elif os.getegid() == 0:
            try:
                # autobind
                conn.do_external_bind(pw_name)
            except errors.NotFound:
                # Fall back
                conn.do_sasl_gssapi_bind()
        else:
            conn.do_sasl_gssapi_bind()
    except (ldap.CONNECT_ERROR, ldap.SERVER_DOWN):
        raise RuntimeError("Unable to connect to LDAP server %s" % fqdn)
    except ldap.INVALID_CREDENTIALS:
        raise RuntimeError(
            "The password provided is incorrect for LDAP server %s" % fqdn)
    except ldap.LOCAL_ERROR, e:
        raise RuntimeError('%s' % e.args[0].get('info', '').strip())
    return conn


class BadSyntax(installutils.ScriptError):
    def __init__(self, value):
        self.value = value
        self.msg = "LDAPUpdate: syntax error: \n  %s" % value
        self.rval = 1

    def __str__(self):
        return repr(self.value)

def safe_output(attr, values):
    """
    Sanitizes values we do not want logged, like passwords.

    This should be called in all debug statements that output values.

    This list does not necessarily need to be exhaustive given the limited
    scope of types of values that the updater manages.

    This only supports lists, tuples and strings. If you pass a dict you may
    get a string back.
    """
    sensitive_attributes = ['krbmkey', 'userpassword', 'passwordhistory', 'krbprincipalkey', 'sambalmpassword', 'sambantpassword', 'ipanthash']

    if attr.lower() in sensitive_attributes:
        if type(values) in (tuple, list):
            # try to still look a little like what is in LDAP
            return ['XXXXXXX'] * len(values)
        else:
            return 'XXXXXXXX'

    if values is None:
        return

    is_list = type(values) in (tuple, list)

    if is_list and None in values:
        return values

    if not is_list:
        values = [values]

    try:
        all(v.decode('ascii') for v in values)
    except UnicodeDecodeError:
        try:
            values = [base64.b64encode(v) for v in values]
        except TypeError:
            pass

    if not is_list:
        values = values[0]
    return values


class LDAPUpdate:
    action_keywords = ["default", "add", "remove", "only", "onlyifexist", "deleteentry", "replace", "addifnew", "addifexist"]

    def __init__(self, dm_password=None, sub_dict={},
                 online=True, ldapi=False):
        '''
        :parameters:
            dm_password
                Directory Manager password
            sub_dict
                substitution dictionary
            online
                Do an online LDAP update or use an experimental LDIF updater
            ldapi
                Bind using ldapi. This assumes autobind is enabled.

        Data Structure Example:
        -----------------------

        dn_by_rdn_count = {
            3: 'cn=config,dc=example,dc=com':
            4: 'cn=bob,ou=people,dc=example,dc=com',
        }

        all_updates = [
            {
                'dn': 'cn=config,dc=example,dc=com',
                'default': [
                    dict(attr='attr1', value='default1'),
                ],
                'updates': [
                    dict(action='action', attr='attr1', value='value1'),
                    dict(action='replace', attr='attr2', value=['old', 'new']),
                ]
            },
            {
                'dn': 'cn=bob,ou=people,dc=example,dc=com',
                'default': [
                    dict(attr='attr3', value='default3'),
                ],
                'updates': [
                    dict(action='action', attr='attr3', value='value3'),
                    dict(action='action', attr='attr4', value='value4'),
                }
            }
        ]

        Please notice the replace action requires two values in list

        The default and update lists are "dispositions"

        Plugins:

        Plugins has to be specified in update file to be executed, using
        'plugin' directive

        Example:
        plugin: update_uniqueness_plugins_to_new_syntax

        Each plugin returns two values:

        1. restart: dirsrv will be restarted AFTER this update is
                     applied.
        2. updates: A list of updates to be applied.

        The value of an update is a dictionary with the following possible
        values:
          - dn: DN, equal to the dn attribute
          - updates: list of updates against the dn
          - default: list of the default entry to be added if it doesn't
                     exist
          - deleteentry: list of dn's to be deleted (typically single dn)

        For example, this update file:

          dn: cn=global_policy,cn=$REALM,cn=kerberos,$SUFFIX
          replace:krbPwdLockoutDuration:10::600
          replace: krbPwdMaxFailure:3::6

        Generates this list which contain the update dictionary:

        [
          {
            'dn': 'cn=global_policy,cn=EXAMPLE.COM,cn=kerberos,dc=example,dc=com',
            'updates': [
              dict(action='replace', attr='krbPwdLockoutDuration',
                   value=['10','600']),
              dict(action='replace', attr='krbPwdMaxFailure',
                   value=['3','6']),
            ]
          }
        ]

        Here is another example showing how a default entry is configured:

          dn: cn=Managed Entries,cn=etc,$SUFFIX
          default: objectClass: nsContainer
          default: objectClass: top
          default: cn: Managed Entries

        This generates:

        [
          {
            'dn': 'cn=Managed Entries,cn=etc,dc=example,dc=com',
            'default': [
              dict(attr='objectClass', value='nsContainer'),
              dict(attr='objectClass', value='top'),
              dict(attr='cn', value='Managed Entries'),
            ]
          }
        ]

        Note that the variable substitution in both examples has been completed.

        Either may make changes directly in LDAP or can return updates in
        update format.

        '''
        log_mgr.get_logger(self, True)
        self.sub_dict = sub_dict
        self.dm_password = dm_password
        self.conn = None
        self.modified = False
        self.online = online
        self.ldapi = ldapi
        self.pw_name = pwd.getpwuid(os.geteuid()).pw_name
        self.realm = None
        self.socket_name = (
            paths.SLAPD_INSTANCE_SOCKET_TEMPLATE %
            api.env.realm.replace('.', '-')
        )
        self.ldapuri = 'ldapi://%s' % ipautil.format_netloc(
            self.socket_name
        )
        suffix = None

        if sub_dict.get("REALM"):
            self.realm = sub_dict["REALM"]
        else:
            krbctx = krbV.default_context()
            try:
                self.realm = krbctx.default_realm
                suffix = ipautil.realm_to_suffix(self.realm)
            except krbV.Krb5Error:
                self.realm = None
                suffix = None

        if suffix is not None:
            assert isinstance(suffix, DN)
        domain = ipautil.get_domain_name()
        libarch = self._identify_arch()

        fqdn = installutils.get_fqdn()
        if fqdn is None:
            raise RuntimeError("Unable to determine hostname")

        if not self.sub_dict.get("REALM") and self.realm is not None:
            self.sub_dict["REALM"] = self.realm
        if not self.sub_dict.get("FQDN"):
            self.sub_dict["FQDN"] = fqdn
        if not self.sub_dict.get("DOMAIN"):
            self.sub_dict["DOMAIN"] = domain
        if not self.sub_dict.get("SUFFIX") and suffix is not None:
            self.sub_dict["SUFFIX"] = suffix
        if not self.sub_dict.get("ESCAPED_SUFFIX"):
            self.sub_dict["ESCAPED_SUFFIX"] = str(suffix)
        if not self.sub_dict.get("LIBARCH"):
            self.sub_dict["LIBARCH"] = libarch
        if not self.sub_dict.get("TIME"):
            self.sub_dict["TIME"] = int(time.time())
        if not self.sub_dict.get("DOMAIN") and domain is not None:
            self.sub_dict["DOMAIN"] = domain
        if not self.sub_dict.get("MIN_DOMAIN_LEVEL"):
            self.sub_dict["MIN_DOMAIN_LEVEL"] = str(constants.MIN_DOMAIN_LEVEL)
        if not self.sub_dict.get("MAX_DOMAIN_LEVEL"):
            self.sub_dict["MAX_DOMAIN_LEVEL"] = str(constants.MAX_DOMAIN_LEVEL)
        self.api = create_api(mode=None)
        self.api.bootstrap(in_server=True, context='updates')
        self.api.finalize()
        if online:
            # Try out the connection/password
            # (This will raise if the server is not available)
            self.create_connection()
            self.close_connection()
        else:
            raise RuntimeError("Offline updates are not supported.")

    def _identify_arch(self):
        """On multi-arch systems some libraries may be in /lib64, /usr/lib64,
           etc.  Determine if a suffix is needed based on the current
           architecture.
        """
        bits = platform.architecture()[0]

        if bits == "64bit":
            return "64"
        else:
            return ""

    def _template_str(self, s):
        try:
            return ipautil.template_str(s, self.sub_dict)
        except KeyError, e:
            raise BadSyntax("Unknown template keyword %s" % e)

    def read_file(self, filename):
        if filename == '-':
            fd = sys.stdin
        else:
            fd = open(filename)
        text = fd.readlines()
        if fd != sys.stdin: fd.close()
        return text

    def parse_update_file(self, data_source_name, source_data, all_updates):
        """Parse the update file into a dictonary of lists and apply the update
           for each DN in the file."""
        update = {}
        logical_line = ""
        dn = None
        lcount = 0

        def emit_item(logical_line):
            '''
            Given a logical line containing an item to process perform the following:

            * Strip leading & trailing whitespace
            * Substitute any variables
            * Get the action, attribute, and value
            * Each update has one list per disposition, append to specified disposition list
            '''

            logical_line = logical_line.strip()
            if logical_line == '':
                return

            # Perform variable substitution on constructued line
            logical_line = self._template_str(logical_line)

            items = logical_line.split(':', 2)

            if len(items) == 0:
                raise BadSyntax, "Bad formatting on line %s:%d: %s" % (data_source_name, lcount, logical_line)

            action = items[0].strip().lower()

            if action not in self.action_keywords:
                raise BadSyntax, "Unknown update action '%s', data source=%s" % (action, data_source_name)

            if action == 'deleteentry':
                new_value = None
                disposition = "deleteentry"
            else:
                if len(items) != 3:
                    raise BadSyntax, "Bad formatting on line %s:%d: %s" % (data_source_name, lcount, logical_line)

                attr = items[1].strip()
                # do not strip here, we need detect '::' due to base64 encoded
                # values, strip may result into fake detection
                value = items[2]

                # detect base64 encoding
                # value which start with ':' are base64 encoded
                # decode it as a binary value
                if value.startswith(':'):
                    value = value[1:]
                    binary = True
                else:
                    binary = False
                value = value.strip()

                if action == 'replace':
                    try:
                        value = value.split('::', 1)
                    except ValueError:
                        raise BadSyntax(
                            "Bad syntax in replace on line %s:%d: %s, needs to "
                            "be in the format old::new in %s" % (
                                data_source_name, lcount, logical_line, value)
                        )
                else:
                    value = [value]

                if binary:
                    for i, v in enumerate(value):
                        try:
                            value[i] = base64.b64decode(v)
                        except TypeError as e:
                            raise BadSyntax(
                                "Base64 encoded value %s on line %s:%d: %s is "
                                "incorrect (%s)" % (v, data_source_name,
                                                    lcount, logical_line, e)
                            )

                if action != 'replace':
                    value = value[0]

                if action == "default":
                    new_value = {'attr': attr, 'value': value}
                    disposition = "default"
                else:
                    new_value = {'action': action, "attr": attr,
                                 'value': value}
                    disposition = "updates"

            disposition_list = update.setdefault(disposition, [])
            disposition_list.append(new_value)

        def emit_update(update):
            '''
            When processing a dn is completed emit the update by appending it
            into list of all updates
            '''
            dn = update.get('dn')
            assert isinstance(dn, DN)
            all_updates.append(update)

        def emit_plugin_update(update):
            '''
            When processing a plugin is complete emit the plugin update by
            appending it into list of all updates
            '''
            all_updates.append(update)

        # Iterate over source input lines
        for source_line in source_data:
            lcount += 1

            # strip trailing whitespace and newline
            source_line = source_line.rstrip()

            # skip comments and empty lines
            if source_line.startswith('#') or source_line == '':
                continue

            state = None
            emit_previous_dn = False

            # parse special keywords
            if source_line.lower().startswith('dn:'):
                state = 'dn'
                emit_previous_dn = True
            elif source_line.lower().startswith('plugin:'):
                state = 'plugin'
                emit_previous_dn = True

            if emit_previous_dn and dn is not None:
                # Emit previous dn
                emit_item(logical_line)
                logical_line = ''
                emit_update(update)
                update = {}
                dn = None

            if state == 'dn':
                # Starting new dn
                dn = source_line[3:].strip()
                dn = DN(self._template_str(dn))
                update['dn'] = dn
            elif state == 'plugin':
                # plugin specification is online only
                plugin_name = source_line[7:].strip()
                if not plugin_name:
                    raise BadSyntax("plugin name is not defined")
                update['plugin'] = plugin_name
                emit_plugin_update(update)
                update = {}
            else:
                # Process items belonging to dn
                if dn is None:
                    raise BadSyntax, "dn is not defined in the update, data source=%s" % (data_source_name)

                # If continuation line, append to existing logical line & continue,
                # otherwise flush the previous item.
                if source_line.startswith(' '):
                    logical_line += source_line[1:]
                    continue
                else:
                    emit_item(logical_line)
                    logical_line = source_line

        if dn is not None:
            emit_item(logical_line)
            logical_line = ''
            emit_update(update)
            update = {}

        return all_updates

    def create_index_task(self, attribute):
        """Create a task to update an index for an attribute"""

        # Sleep a bit to ensure previous operations are complete
        time.sleep(5)

        cn_uuid = uuid.uuid1()
        # cn_uuid.time is in nanoseconds, but other users of LDAPUpdate expect
        # seconds in 'TIME' so scale the value down
        self.sub_dict['TIME'] = int(cn_uuid.time/1e9)
        cn = "indextask_%s_%s_%s" % (attribute, cn_uuid.time, cn_uuid.clock_seq)
        dn = DN(('cn', cn), ('cn', 'index'), ('cn', 'tasks'), ('cn', 'config'))

        e = self.conn.make_entry(
            dn,
            objectClass=['top', 'extensibleObject'],
            cn=[cn],
            nsInstance=['userRoot'],
            nsIndexAttribute=[attribute],
        )

        self.debug("Creating task to index attribute: %s", attribute)
        self.debug("Task id: %s", dn)

        self.conn.add_entry(e)

        return dn

    def monitor_index_task(self, dn):
        """Give a task DN monitor it and wait until it has completed (or failed)
        """

        assert isinstance(dn, DN)

        # Pause for a moment to give the task time to be created
        time.sleep(1)

        attrlist = ['nstaskstatus', 'nstaskexitcode']
        entry = None

        while True:
            try:
                entry = self.conn.get_entry(dn, attrlist)
            except errors.NotFound, e:
                self.error("Task not found: %s", dn)
                return
            except errors.DatabaseError, e:
                self.error("Task lookup failure %s", e)
                return

            status = entry.single_value.get('nstaskstatus')
            if status is None:
                # task doesn't have a status yet
                time.sleep(1)
                continue

            if status.lower().find("finished") > -1:
                self.debug("Indexing finished")
                break

            self.debug("Indexing in progress")
            time.sleep(1)

        return

    def _create_default_entry(self, dn, default):
        """Create the default entry from the values provided.

           The return type is ipaldap.LDAPEntry
        """
        assert isinstance(dn, DN)
        entry = self.conn.make_entry(dn)

        if not default:
            # This means that the entire entry needs to be created with add
            return entry

        for item in default:
            # We already do syntax-parsing so this is safe
            attr = item['attr']
            value = item['value']

            e = entry.get(attr)
            if e:
                # multi-valued attribute
                e = list(e)
                e.append(value)
            else:
                e = [value]
            entry[attr] = e
        entry.reset_modlist()

        return entry

    def _get_entry(self, dn):
        """Retrieve an object from LDAP.

           The return type is ipaldap.LDAPEntry
        """
        assert isinstance(dn, DN)
        searchfilter="objectclass=*"
        sattrs = ["*", "aci", "attributeTypes", "objectClasses"]
        scope = ldap.SCOPE_BASE

        return self.conn.get_entries(dn, scope, searchfilter, sattrs)

    def _apply_update_disposition(self, updates, entry):
        """
        updates is a list of changes to apply
        entry is the thing to apply them to

        Returns the modified entry
        """
        if not updates:
            return entry

        only = {}
        for update in updates:
            # We already do syntax-parsing so this is safe
            action = update['action']
            attr = update['attr']
            update_value = update['value']

            entry_values = entry.raw.get(attr, [])
            if action == 'remove':
                self.debug("remove: '%s' from %s, current value %s", safe_output(attr, update_value), attr, safe_output(attr,entry_values))
                try:
                    entry_values.remove(update_value)
                except ValueError:
                    self.debug("remove: '%s' not in %s", update_value, attr)
                else:
                    entry[attr] = entry_values
                    self.debug('remove: updated value %s', safe_output(
                        attr, entry_values))
            elif action == 'add':
                self.debug("add: '%s' to %s, current value %s", safe_output(attr, update_value), attr, safe_output(attr, entry_values))
                # Remove it, ignoring errors so we can blindly add it later
                try:
                    entry_values.remove(update_value)
                except ValueError:
                    pass
                entry_values.append(update_value)
                self.debug('add: updated value %s', safe_output(attr, entry_values))
                entry[attr] = entry_values
            elif action == 'addifnew':
                self.debug("addifnew: '%s' to %s, current value %s", safe_output(attr, update_value), attr, safe_output(attr, entry_values))
                # Only add the attribute if it doesn't exist. Only works
                # with single-value attributes.
                if len(entry_values) == 0:
                    entry_values.append(update_value)
                    self.debug('addifnew: set %s to %s', attr, safe_output(attr, entry_values))
                    entry[attr] = entry_values
            elif action == 'addifexist':
                self.debug("addifexist: '%s' to %s, current value %s", safe_output(attr, update_value), attr, safe_output(attr, entry_values))
                # Only add the attribute if the entry doesn't exist. We
                # determine this based on whether it has an objectclass
                if entry.get('objectclass'):
                    entry_values.append(update_value)
                    self.debug('addifexist: set %s to %s', attr, safe_output(attr, entry_values))
                    entry[attr] = entry_values
            elif action == 'only':
                self.debug("only: set %s to '%s', current value %s", attr, safe_output(attr, update_value), safe_output(attr, entry_values))
                if only.get(attr):
                    entry_values.append(update_value)
                else:
                    entry_values = [update_value]
                    only[attr] = True
                entry[attr] = entry_values
                self.debug('only: updated value %s', safe_output(attr, entry_values))
            elif action == 'onlyifexist':
                self.debug("onlyifexist: '%s' to %s, current value %s", safe_output(attr, update_value), attr, safe_output(attr, entry_values))
                # Only set the attribute if the entry exist's. We
                # determine this based on whether it has an objectclass
                if entry.get('objectclass'):
                    if only.get(attr):
                        entry_values.append(update_value)
                    else:
                        entry_values = [update_value]
                        only[attr] = True
                    self.debug('onlyifexist: set %s to %s', attr, safe_output(attr, entry_values))
                    entry[attr] = entry_values
            elif action == 'deleteentry':
                # skip this update type, it occurs in  __delete_entries()
                return None
            elif action == 'replace':
                # replace values were store as list
                old, new = update_value

                try:
                    entry_values.remove(old)
                except ValueError:
                    self.debug('replace: %s not found, skipping', safe_output(attr, old))
                else:
                    entry_values.append(new)
                    self.debug('replace: updated value %s', safe_output(attr, entry_values))
                    entry[attr] = entry_values

        return entry

    def print_entity(self, e, message=None):
        """The entity object currently lacks a str() method"""
        self.debug("---------------------------------------------")
        if message:
            self.debug("%s", message)
        self.debug("dn: %s", e.dn)
        for a, value in e.raw.items():
            self.debug('%s:', a)
            for l in value:
                self.debug("\t%s", safe_output(a, l))

    def _update_record(self, update):
        found = False

        new_entry = self._create_default_entry(update.get('dn'),
                                               update.get('default'))

        try:
            e = self._get_entry(new_entry.dn)
            if len(e) > 1:
                # we should only ever get back one entry
                raise BadSyntax, "More than 1 entry returned on a dn search!? %s" % new_entry.dn
            entry = e[0]
            found = True
            self.debug("Updating existing entry: %s", entry.dn)
        except errors.NotFound:
            # Doesn't exist, start with the default entry
            entry = new_entry
            self.debug("New entry: %s", entry.dn)
        except errors.DatabaseError:
            # Doesn't exist, start with the default entry
            entry = new_entry
            self.debug("New entry, using default value: %s", entry.dn)

        self.print_entity(entry, "Initial value")

        # Bring this entry up to date
        entry = self._apply_update_disposition(update.get('updates'), entry)
        if entry is None:
            # It might be None if it is just deleting an entry
            return

        self.print_entity(entry, "Final value after applying updates")

        added = False
        updated = False
        if not found:
            try:
                if len(entry):
                    # addifexist may result in an entry with only a
                    # dn defined. In that case there is nothing to do.
                    # It means the entry doesn't exist, so skip it.
                    try:
                        self.conn.add_entry(entry)
                    except errors.NotFound:
                        # parent entry of the added entry does not exist
                        # this may not be an error (e.g. entries in NIS container)
                        self.error("Parent DN of %s may not exist, cannot "
                                   "create the entry", entry.dn)
                        return
                added = True
                self.modified = True
            except Exception, e:
                self.error("Add failure %s", e)
        else:
            # Update LDAP
            try:
                changes = entry.generate_modlist()
                if len(changes) >= 1:
                    updated = True
                safe_changes = []
                for (type, attr, values) in changes:
                    safe_changes.append((type, attr, safe_output(attr, values)))
                self.debug("%s" % safe_changes)
                self.debug("Updated %d" % updated)
                if updated:
                    self.conn.update_entry(entry)
                self.debug("Done")
            except errors.EmptyModlist:
                self.debug("Entry already up-to-date")
                updated = False
            except errors.DatabaseError, e:
                self.error("Update failed: %s", e)
                updated = False
            except errors.ACIError, e:
                self.error("Update failed: %s", e)
                updated = False

            if updated:
                self.modified = True

        if entry.dn.endswith(DN(('cn', 'index'), ('cn', 'userRoot'),
                                ('cn', 'ldbm database'), ('cn', 'plugins'),
                                ('cn', 'config'))) and (added or updated):
            taskid = self.create_index_task(entry.single_value['cn'])
            self.monitor_index_task(taskid)
        return

    def _delete_record(self, updates):
        """
        Delete record
        """

        dn = updates['dn']
        try:
            self.debug("Deleting entry %s", dn)
            self.conn.delete_entry(dn)
            self.modified = True
        except errors.NotFound, e:
            self.debug("%s did not exist:%s", dn, e)
            self.modified = True
        except errors.DatabaseError, e:
            self.error("Delete failed: %s", e)

    def get_all_files(self, root, recursive=False):
        """Get all update files"""
        f = []
        for path, subdirs, files in os.walk(root):
            for name in files:
                if fnmatch.fnmatch(name, "*.update"):
                    f.append(os.path.join(path, name))
            if not recursive:
                break
        f.sort()
        return f

    def _run_update_plugin(self, plugin_name):
        self.log.debug("Executing upgrade plugin: %s", plugin_name)
        restart_ds, updates = self.api.Updater[plugin_name]()
        if updates:
            self._run_updates(updates)
        # restart may be required even if no updates were returned
        # from plugin, plugin may change LDAP data directly
        if restart_ds:
            self.close_connection()
            self.restart_ds()
            self.create_connection()

    def create_connection(self):
        if self.online:
            self.api.Backend.ldap2.connect(
                bind_dn=DN(('cn', 'Directory Manager')),
                bind_pw=self.dm_password,
                autobind=self.ldapi)
            self.conn = self.api.Backend.ldap2
        else:
            raise RuntimeError("Offline updates are not supported.")

    def _run_updates(self, all_updates):
        for update in all_updates:
            if 'deleteentry' in update:
                self._delete_record(update)
            elif 'plugin' in update:
                self._run_update_plugin(update['plugin'])
            else:
                self._update_record(update)

    def update(self, files, ordered=True):
        """Execute the update. files is a list of the update files to use.
        :param ordered: Update files are executed in alphabetical order

        returns True if anything was changed, otherwise False
        """
        self.modified = False
        all_updates = []
        try:
            self.create_connection()

            upgrade_files = files
            if ordered:
                upgrade_files = sorted(files)

            for f in upgrade_files:
                try:
                    self.debug("Parsing update file '%s'" % f)
                    data = self.read_file(f)
                except Exception, e:
                    self.error("error reading update file '%s'", f)
                    raise RuntimeError(e)

                self.parse_update_file(f, data, all_updates)
                self._run_updates(all_updates)
                all_updates = []
        finally:
            self.close_connection()

        return self.modified

    def update_from_dict(self, updates):
        """
        Apply updates internally as opposed to from a file.
        updates is a dictionary containing the updates
        """
        self.modified = False
        try:
            self.create_connection()
            self._run_updates(updates)
        finally:
            self.close_connection()

        return self.modified

    def close_connection(self):
        """Close ldap connection"""
        if self.conn:
            self.api.Backend.ldap2.disconnect()
            self.conn = None

    def restart_ds(self):
        dirsrv = services.knownservices.dirsrv
        self.log.debug('Restarting directory server to apply updates')
        dirsrv.restart()
        wait_for_open_socket(self.socket_name)
