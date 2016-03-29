#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from collections import namedtuple

from ipalib import _
from ipalib import Command
from ipalib import errors
from ipalib import output
from ipalib.parameters import Int
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import LDAPObject, LDAPUpdate, LDAPRetrieve

from ipapython.dn import DN


__doc__ = _("""
Raise the IPA Domain Level.
""")

register = Registry()

DomainLevelRange = namedtuple('DomainLevelRange', ['min', 'max'])

domainlevel_output = (
    output.Output('result', int, _('Current domain level:')),
)


def get_domainlevel_dn(api):
    domainlevel_dn = DN(
        ('cn', 'Domain Level'),
        ('cn', 'ipa'),
        ('cn', 'etc'),
        api.env.basedn
    )

    return domainlevel_dn


def get_domainlevel_range(master_entry):
    try:
        return DomainLevelRange(
            int(master_entry['ipaMinDomainLevel'][0]),
            int(master_entry['ipaMaxDomainLevel'][0])
        )
    except KeyError:
        return DomainLevelRange(0, 0)


def get_master_entries(ldap, api):
    """
    Returns list of LDAPEntries representing IPA masters.
    """

    container_masters = DN(
        ('cn', 'masters'),
        ('cn', 'ipa'),
        ('cn', 'etc'),
        api.env.basedn
    )

    masters, _ = ldap.find_entries(
        filter="(cn=*)",
        base_dn=container_masters,
        scope=ldap.SCOPE_ONELEVEL,
        paged_search=True,  # we need to make sure to get all of them
    )

    return masters


@register()
class domainlevel_get(Command):
    __doc__ = _('Query current Domain Level.')
    NO_CLI = True

    has_output = domainlevel_output

    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2
        entry = ldap.get_entry(
            get_domainlevel_dn(self.api),
            ['ipaDomainLevel']
        )

        return {'result': int(entry.single_value['ipaDomainLevel'])}


@register()
class domainlevel_set(Command):
    __doc__ = _('Change current Domain Level.')
    NO_CLI = True

    has_output = domainlevel_output

    takes_args = (
        Int('ipadomainlevel',
            cli_name='level',
            label=_('Domain Level'),
            minvalue=0,
        ),
    )

    def execute(self, *args, **options):
        """
        Checks all the IPA masters for supported domain level ranges.

        If the desired domain level is within the supported range of all
        masters, it will be raised.

        Domain level cannot be lowered.
        """

        ldap = self.api.Backend.ldap2

        current_entry = ldap.get_entry(get_domainlevel_dn(self.api))
        current_value = int(current_entry.single_value['ipadomainlevel'])
        desired_value = int(args[0])

        # Domain level cannot be lowered
        if int(desired_value) < int(current_value):
            message = _("Domain Level cannot be lowered.")
            raise errors.InvalidDomainLevelError(message)

        # Check if every master supports the desired level
        for master in get_master_entries(ldap, self.api):
            supported = get_domainlevel_range(master)

            if supported.min > desired_value or supported.max < desired_value:
                message = _("Domain Level cannot be raised to {0}, server {1} "
                            "does not support it."
                            .format(desired_value, master['cn'][0]))
                raise errors.InvalidDomainLevelError(message)

        current_entry.single_value['ipaDomainLevel'] = desired_value
        ldap.update_entry(current_entry)

        return {'result': int(current_entry.single_value['ipaDomainLevel'])}
