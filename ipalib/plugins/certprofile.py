#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import re

from ipalib import api, Bool, File, Str
from ipalib import output, util
from ipalib.plugable import Registry
from ipalib.plugins.virtual import VirtualCommand
from ipalib.plugins.baseldap import (
    LDAPObject, LDAPSearch, LDAPCreate,
    LDAPDelete, LDAPUpdate, LDAPRetrieve)
from ipalib import ngettext
from ipalib.text import _
from ipapython.version import API_VERSION

from ipalib import errors


__doc__ = _("""
Manage Certificate Profiles

Certificate Profiles are used by Certificate Authority (CA) in the signing of
certificates to determine if a Certificate Signing Request (CSR) is acceptable,
and if so what features and extensions will be present on the certificate.

The Certificate Profile format is the property-list format understood by the
Dogtag or Red Hat Certificate System CA.

PROFILE ID SYNTAX:

A Profile ID is a string without spaces or punctuation starting with a letter
and followed by a sequence of letters, digits or underscore ("_").

EXAMPLES:

  Import a profile that will not store issued certificates:
    ipa certprofile-import ShortLivedUserCert \\
      --file UserCert.profile --desc "User Certificates" \\
      --store=false

  Delete a certificate profile:
    ipa certprofile-del ShortLivedUserCert

  Show information about a profile:
    ipa certprofile-show ShortLivedUserCert

  Search for profiles that do not store certificates:
    ipa certprofile-find --store=false

""")


register = Registry()


def ca_enabled_check():
    """Raise NotFound if CA is not enabled.

    This function is defined in multiple plugins to avoid circular imports
    (cert depends on certprofile, so we cannot import cert here).

    """
    if not api.Command.ca_is_enabled()['result']:
        raise errors.NotFound(reason=_('CA is not configured'))


profile_id_pattern = re.compile('^[a-zA-Z]\w*$')


def validate_profile_id(ugettext, value):
    """Ensure profile ID matches form required by CA."""
    if profile_id_pattern.match(value) is None:
        return _('invalid Profile ID')
    else:
        return None


@register()
class certprofile(LDAPObject):
    """
    Certificate Profile object.
    """
    container_dn = api.env.container_certprofile
    object_name = _('Certificate Profile')
    object_name_plural = _('Certificate Profiles')
    object_class = ['ipacertprofile']
    default_attributes = [
        'cn', 'description', 'ipacertprofilestoreissued'
    ]
    search_attributes = [
        'cn', 'description', 'ipacertprofilestoreissued'
    ]
    rdn_is_primary_key = True
    label = _('Certificate Profiles')
    label_singular = _('Certificate Profile')

    takes_params = (
        Str('cn', validate_profile_id,
            primary_key=True,
            cli_name='id',
            label=_('Profile ID'),
            doc=_('Profile ID for referring to this profile'),
        ),
        Str('description',
            required=True,
            cli_name='desc',
            label=_('Profile description'),
            doc=_('Brief description of this profile'),
        ),
        Bool('ipacertprofilestoreissued',
            default=True,
            cli_name='store',
            label=_('Store issued certificates'),
            doc=_('Whether to store certs issued using this profile'),
        ),
    )

    permission_filter_objectclasses = ['ipacertprofile']
    managed_permissions = {
        'System: Read Certificate Profiles': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn',
                'description',
                'ipacertprofilestoreissued',
                'objectclass',
            },
        },
        'System: Import Certificate Profile': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=certprofiles,cn=ca,$SUFFIX")(version 3.0;acl "permission:Import Certificate Profile";allow (add) groupdn = "ldap:///cn=Import Certificate Profile,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
        'System: Delete Certificate Profile': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=certprofiles,cn=ca,$SUFFIX")(version 3.0;acl "permission:Delete Certificate Profile";allow (delete) groupdn = "ldap:///cn=Delete Certificate Profile,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
        'System: Modify Certificate Profile': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'cn',
                'description',
                'ipacertprofilestoreissued',
            },
            'replaces': [
                '(targetattr = "cn || description || ipacertprofilestoreissued")(target = "ldap:///cn=*,cn=certprofiles,cn=ca,$SUFFIX")(version 3.0;acl "permission:Modify Certificate Profile";allow (write) groupdn = "ldap:///cn=Modify Certificate Profile,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
    }



@register()
class certprofile_find(LDAPSearch):
    __doc__ = _("Search for Certificate Profiles.")
    msg_summary = ngettext(
        '%(count)d profile matched', '%(count)d profiles matched', 0
    )

    def execute(self, *args, **kwargs):
        ca_enabled_check()
        return super(certprofile_find, self).execute(*args, **kwargs)


@register()
class certprofile_show(LDAPRetrieve):
    __doc__ = _("Display the properties of a Certificate Profile.")

    has_output_params = LDAPRetrieve.has_output_params + (
        Str('config',
            label=_('Profile configuration'),
        ),
    )

    takes_options = LDAPRetrieve.takes_options + (
        Str('out?',
            doc=_('Write profile configuration to file'),
        ),
    )

    def execute(self, *keys, **options):
        ca_enabled_check()
        result = super(certprofile_show, self).execute(*keys, **options)

        if 'out' in options:
            with self.api.Backend.ra_certprofile as profile_api:
                result['result']['config'] = profile_api.read_profile(keys[0])

        return result

    def forward(self, *keys, **options):
        if 'out' in options:
            util.check_writable_file(options['out'])

        result = super(certprofile_show, self).forward(*keys, **options)
        if 'out' in options and 'config' in result['result']:
            with open(options['out'], 'w') as f:
                f.write(result['result'].pop('config'))
            result['summary'] = (
                _("Profile configuration stored in file '%(file)s'")
                % dict(file=options['out'])
            )

        return result


@register()
class certprofile_import(LDAPCreate):
    __doc__ = _("Import a Certificate Profile.")
    msg_summary = _('Imported profile "%(value)s"')
    takes_options = (
        File('file',
            label=_('Filename'),
            cli_name='file',
            flags=('virtual_attribute',),
        ),
    )

    PROFILE_ID_PATTERN = re.compile('^profileId=([a-zA-Z]\w*)', re.MULTILINE)

    def pre_callback(self, ldap, dn, entry, entry_attrs, *keys, **options):
        ca_enabled_check()

        match = self.PROFILE_ID_PATTERN.search(options['file'])
        if match is None:
            raise errors.ValidationError(name='file',
                error=_("Profile ID is not present in profile data"))
        elif keys[0] != match.group(1):
            raise errors.ValidationError(name='file',
                error=_("Profile ID '%(cli_value)s' does not match profile data '%(file_value)s'")
                    % {'cli_value': keys[0], 'file_value': match.group(1)}
            )
        return dn


    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        """Import the profile into Dogtag and enable it.

        If the operation fails, remove the LDAP entry.
        """
        try:
            with self.api.Backend.ra_certprofile as profile_api:
                profile_api.create_profile(options['file'])
                profile_api.enable_profile(keys[0])
        except:
            # something went wrong ; delete entry
            ldap.delete_entry(dn)
            raise

        return dn


@register()
class certprofile_del(LDAPDelete):
    __doc__ = _("Delete a Certificate Profile.")
    msg_summary = _('Deleted profile "%(value)s"')

    def execute(self, *args, **kwargs):
        ca_enabled_check()
        return super(certprofile_del, self).execute(*args, **kwargs)

    def post_callback(self, ldap, dn, *keys, **options):
        with self.api.Backend.ra_certprofile as profile_api:
            profile_api.disable_profile(keys[0])
            profile_api.delete_profile(keys[0])
        return dn


@register()
class certprofile_mod(LDAPUpdate):
    __doc__ = _("Modify Certificate Profile configuration.")
    msg_summary = _('Modified Certificate Profile "%(value)s"')

    takes_options = LDAPUpdate.takes_options + (
        File('file?',
            label=_('File containing profile configuration'),
            cli_name='file',
            flags=('virtual_attribute',),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        ca_enabled_check()
        if 'file' in options:
            with self.api.Backend.ra_certprofile as profile_api:
                profile_api.disable_profile(keys[0])
                try:
                    profile_api.update_profile(keys[0], options['file'])
                finally:
                    profile_api.enable_profile(keys[0])

        return dn

    def execute(self, *keys, **options):
        try:
            return super(certprofile_mod, self).execute(*keys, **options)
        except errors.EmptyModlist:
            if 'file' in options:
                # The profile data in Dogtag was updated.
                # Do not fail; return result of certprofile-show instead
                return self.api.Command.certprofile_show(keys[0],
                    version=API_VERSION)
            else:
                # This case is actually an error; re-raise
                raise
