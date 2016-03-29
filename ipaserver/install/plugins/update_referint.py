#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from ipalib import api, errors
from ipalib import Updater
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger

class update_referint(Updater):
    """
    Update referential integrity configuration to new style
    http://directory.fedoraproject.org/docs/389ds/design/ri-plugin-configuration.html

    old attr              -> new attr
    nsslapd-pluginArg0    -> referint-update-delay
    nsslapd-pluginArg1    -> referint-logfile
    nsslapd-pluginArg2    -> referint-logchanges
    nsslapd-pluginArg3..N -> referint-membership-attr [3..N]

    Old and new style cannot be mixed, all nslapd-pluginArg* attrs have to be removed
    """

    referint_dn = DN(('cn', 'referential integrity postoperation'),
                           ('cn', 'plugins'), ('cn', 'config'))

    def execute(self, **options):

        root_logger.debug("Upgrading referential integrity plugin configuration")
        ldap = self.api.Backend.ldap2
        try:
            entry = ldap.get_entry(self.referint_dn)
        except errors.NotFound:
            root_logger.error("Referential integrity configuration not found")
            return False, []

        referint_membership_attrs = []

        root_logger.debug("Initial value: %s", repr(entry))

        # nsslapd-pluginArg0    -> referint-update-delay
        update_delay = entry.get('nsslapd-pluginArg0')
        if update_delay:
            root_logger.debug("add: referint-update-delay: %s", update_delay)
            entry['referint-update-delay'] = update_delay
            entry['nsslapd-pluginArg0'] = None
        else:
            root_logger.debug("Plugin already uses new style, skipping")
            return False, []

        # nsslapd-pluginArg1    -> referint-logfile
        logfile = entry.get('nsslapd-pluginArg1')
        if logfile:
            root_logger.debug("add: referint-logfile: %s", logfile)
            entry['referint-logfile'] = logfile
            entry['nsslapd-pluginArg1'] = None

        # nsslapd-pluginArg2    -> referint-logchanges
        logchanges = entry.get('nsslapd-pluginArg2')
        if logchanges:
            root_logger.debug("add: referint-logchanges: %s", logchanges)
            entry['referint-logchanges'] = logchanges
            entry['nsslapd-pluginArg2'] = None

        # nsslapd-pluginArg3..N -> referint-membership-attr [3..N]
        for key in entry.keys():
            if key.lower().startswith('nsslapd-pluginarg'):
                arg_val = entry.single_value[key]
                if arg_val:
                    referint_membership_attrs.append(arg_val)
                entry[key] = None

        if referint_membership_attrs:
            # entry['referint-membership-attr'] is None, plugin doesn't allow
            # mixing old and new style
            entry['referint-membership-attr'] = referint_membership_attrs

        root_logger.debug("Final value: %s", repr(entry))
        try:
            ldap.update_entry(entry)
        except errors.EmptyModlist:
            root_logger.debug("No modifications required")
            return False, []

        return False, []

api.register(update_referint)
