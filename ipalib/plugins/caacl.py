#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import pyhbac

from ipalib import api, errors, output
from ipalib import Bool, Str, StrEnum
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import (
    LDAPObject, LDAPSearch, LDAPCreate, LDAPDelete, LDAPQuery,
    LDAPUpdate, LDAPRetrieve, LDAPAddMember, LDAPRemoveMember,
    global_output_params, pkey_to_value)
from ipalib.plugins.hbacrule import is_all
from ipalib.plugins.service import normalize_principal, split_any_principal
from ipalib import _, ngettext
from ipapython.dn import DN


__doc__ = _("""
Manage CA ACL rules.

This plugin is used to define rules governing which principals are
permitted to have certificates issued using a given certificate
profile.

PROFILE ID SYNTAX:

A Profile ID is a string without spaces or punctuation starting with a letter
and followed by a sequence of letters, digits or underscore ("_").

EXAMPLES:

  Create a CA ACL "test" that grants all users access to the
  "UserCert" profile:
    ipa caacl-add test --usercat=all
    ipa caacl-add-profile test --certprofiles UserCert

  Display the properties of a named CA ACL:
    ipa caacl-show test

  Create a CA ACL to let user "alice" use the "DNP3" profile:
    ipa caacl-add-profile alice_dnp3 --certprofiles DNP3
    ipa caacl-add-user alice_dnp3 --user=alice

  Disable a CA ACL:
    ipa caacl-disable test

  Remove a CA ACL:
    ipa caacl-del test
""")

register = Registry()


def _acl_make_request(principal_type, principal, ca_ref, profile_id):
    """Construct HBAC request for the given principal, CA and profile"""
    service, name, realm = split_any_principal(principal)

    req = pyhbac.HbacRequest()
    req.targethost.name = ca_ref
    req.service.name = profile_id
    if principal_type == 'user':
        req.user.name = principal
    elif principal_type == 'host':
        req.user.name = name
    elif principal_type == 'service':
        req.user.name = normalize_principal(principal)
    groups = []
    if principal_type == 'user':
        user_obj = api.Command.user_show(principal)['result']
        groups = user_obj.get('memberof_group', [])
        groups += user_obj.get('memberofindirect_group', [])
    elif principal_type == 'host':
        host_obj = api.Command.host_show(name)['result']
        groups = host_obj.get('memberof_hostgroup', [])
        groups += host_obj.get('memberofindirect_hostgroup', [])
    req.user.groups = sorted(set(groups))
    return req


def _acl_make_rule(principal_type, obj):
    """Turn CA ACL object into HBAC rule.

    ``principal_type``
        String in {'user', 'host', 'service'}
    """
    rule = pyhbac.HbacRule(obj['cn'][0])
    rule.enabled = obj['ipaenabledflag'][0]
    rule.srchosts.category = {pyhbac.HBAC_CATEGORY_ALL}

    # add CA(s)
    # Hardcoded until caacl plugin arrives
    rule.targethosts.category = {pyhbac.HBAC_CATEGORY_ALL}
    #if 'ipacacategory' in obj and obj['ipacacategory'][0].lower() == 'all':
    #    rule.targethosts.category = {pyhbac.HBAC_CATEGORY_ALL}
    #else:
    #    rule.targethosts.names = obj.get('ipacaaclcaref', [])

    # add profiles
    if ('ipacertprofilecategory' in obj
            and obj['ipacertprofilecategory'][0].lower() == 'all'):
        rule.services.category = {pyhbac.HBAC_CATEGORY_ALL}
    else:
        attr = 'ipamembercertprofile_certprofile'
        rule.services.names = obj.get(attr, [])

    # add principals and principal's groups
    m = {'user': 'group', 'host': 'hostgroup', 'service': None}
    category_attr = '{}category'.format(principal_type)
    if category_attr in obj and obj[category_attr][0].lower() == 'all':
        rule.users.category = {pyhbac.HBAC_CATEGORY_ALL}
    else:
        principal_attr = 'member{}_{}'.format(principal_type, principal_type)
        rule.users.names = obj.get(principal_attr, [])
        if m[principal_type] is not None:
            group_attr = 'member{}_{}'.format(principal_type, m[principal_type])
            rule.users.groups = obj.get(group_attr, [])

    return rule


def acl_evaluate(principal_type, principal, ca_ref, profile_id):
    req = _acl_make_request(principal_type, principal, ca_ref, profile_id)
    acls = api.Command.caacl_find()['result']
    rules = [_acl_make_rule(principal_type, obj) for obj in acls]
    return req.evaluate(rules) == pyhbac.HBAC_EVAL_ALLOW


@register()
class caacl(LDAPObject):
    """
    CA ACL object.
    """
    container_dn = api.env.container_caacl
    object_name = _('CA ACL')
    object_name_plural = _('CA ACLs')
    object_class = ['ipaassociation', 'ipacaacl']
    permission_filter_objectclasses = ['ipacaacl']
    default_attributes = [
        'cn', 'description', 'ipaenabledflag',
        'ipacacategory', 'ipamemberca',
        'ipacertprofilecategory', 'ipamembercertprofile',
        'usercategory', 'memberuser',
        'hostcategory', 'memberhost',
        'servicecategory', 'memberservice',
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'memberservice': ['service'],
        'ipamembercertprofile': ['certprofile'],
    }
    managed_permissions = {
        'System: Read CA ACLs': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'description', 'ipaenabledflag',
                'ipacacategory', 'ipamemberca',
                'ipacertprofilecategory', 'ipamembercertprofile',
                'usercategory', 'memberuser',
                'hostcategory', 'memberhost',
                'servicecategory', 'memberservice',
                'ipauniqueid',
                'objectclass', 'member',
            },
        },
        'System: Add CA ACL': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=caacls,cn=ca,$SUFFIX")(version 3.0;acl "permission:Add CA ACL";allow (add) groupdn = "ldap:///cn=Add CA ACL,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
        'System: Delete CA ACL': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=caacls,cn=ca,$SUFFIX")(version 3.0;acl "permission:Delete CA ACL";allow (delete) groupdn = "ldap:///cn=Delete CA ACL,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
        'System: Manage CA ACL Membership': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'ipacacategory', 'ipamemberca',
                'ipacertprofilecategory', 'ipamembercertprofile',
                'usercategory', 'memberuser',
                'hostcategory', 'memberhost',
                'servicecategory', 'memberservice'
            },
            'replaces': [
                '(targetattr = "ipamemberca || ipamembercertprofile || memberuser || memberservice || memberhost || ipacacategory || ipacertprofilecategory || usercategory || hostcategory || servicecategory")(target = "ldap:///ipauniqueid=*,cn=caacls,cn=ca,$SUFFIX")(version 3.0;acl "permission:Manage CA ACL membership";allow (write) groupdn = "ldap:///cn=Manage CA ACL membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
        'System: Modify CA ACL': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'cn', 'description', 'ipaenabledflag',
            },
            'replaces': [
                '(targetattr = "cn || description || ipaenabledflag")(target = "ldap:///ipauniqueid=*,cn=caacls,cn=ca,$SUFFIX")(version 3.0;acl "permission:Modify CA ACL";allow (write) groupdn = "ldap:///cn=Modify CA ACL,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
    }

    label = _('CA ACLs')
    label_singular = _('CA ACL')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('ACL name'),
            primary_key=True,
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
        Bool('ipaenabledflag?',
             label=_('Enabled'),
             flags=['no_option'],
        ),
        # Commented until subca plugin arrives
        #StrEnum('ipacacategory?',
        #    cli_name='cacat',
        #    label=_('CA category'),
        #    doc=_('CA category the ACL applies to'),
        #    values=(u'all', ),
        #),
        StrEnum('ipacertprofilecategory?',
            cli_name='profilecat',
            label=_('Profile category'),
            doc=_('Profile category the ACL applies to'),
            values=(u'all', ),
        ),
        StrEnum('usercategory?',
            cli_name='usercat',
            label=_('User category'),
            doc=_('User category the ACL applies to'),
            values=(u'all', ),
        ),
        StrEnum('hostcategory?',
            cli_name='hostcat',
            label=_('Host category'),
            doc=_('Host category the ACL applies to'),
            values=(u'all', ),
        ),
        StrEnum('servicecategory?',
            cli_name='servicecat',
            label=_('Service category'),
            doc=_('Service category the ACL applies to'),
            values=(u'all', ),
        ),
        # Commented until subca plugin arrives
        #Str('ipamemberca_subca?',
        #    label=_('CAs'),
        #    flags=['no_create', 'no_update', 'no_search'],
        #),
        Str('ipamembercertprofile_certprofile?',
            label=_('Profiles'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberuser_user?',
            label=_('Users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberuser_group?',
            label=_('User Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_host?',
            label=_('Hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_hostgroup?',
            label=_('Host Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberservice_service?',
            label=_('Services'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )


@register()
class caacl_add(LDAPCreate):
    __doc__ = _('Create a new CA ACL.')

    msg_summary = _('Added CA ACL "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # CA ACLs are enabled by default
        entry_attrs['ipaenabledflag'] = ['TRUE']
        return dn


@register()
class caacl_del(LDAPDelete):
    __doc__ = _('Delete a CA ACL.')

    msg_summary = _('Deleted CA ACL "%(value)s"')


@register()
class caacl_mod(LDAPUpdate):
    __doc__ = _('Modify a CA ACL.')

    msg_summary = _('Modified CA ACL "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, attrs_list)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        # Commented until subca plugin arrives
        #if is_all(options, 'ipacacategory') and 'ipamemberca' in entry_attrs:
        #    raise errors.MutuallyExclusiveError(reason=_(
        #        "CA category cannot be set to 'all' "
        #        "while there are allowed CAs"))
        if (is_all(options, 'ipacertprofilecategory')
                and 'ipamembercertprofile' in entry_attrs):
            raise errors.MutuallyExclusiveError(reason=_(
                "profile category cannot be set to 'all' "
                "while there are allowed profiles"))
        if is_all(options, 'usercategory') and 'memberuser' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_(
                "user category cannot be set to 'all' "
                "while there are allowed users"))
        if is_all(options, 'hostcategory') and 'memberhost' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_(
                "host category cannot be set to 'all' "
                "while there are allowed hosts"))
        if is_all(options, 'servicecategory') and 'memberservice' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_(
                "service category cannot be set to 'all' "
                "while there are allowed services"))
        return dn


@register()
class caacl_find(LDAPSearch):
    __doc__ = _('Search for CA ACLs.')

    msg_summary = ngettext(
        '%(count)d CA ACL matched', '%(count)d CA ACLs matched', 0
    )


@register()
class caacl_show(LDAPRetrieve):
    __doc__ = _('Display the properties of a CA ACL.')


@register()
class caacl_enable(LDAPQuery):
    __doc__ = _('Enable a CA ACL.')

    msg_summary = _('Enabled CA ACL "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['TRUE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )


@register()
class caacl_disable(LDAPQuery):
    __doc__ = _('Disable a CA ACL.')

    msg_summary = _('Disabled CA ACL "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['FALSE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )


@register()
class caacl_add_user(LDAPAddMember):
    __doc__ = _('Add users and groups to a CA ACL.')

    member_attributes = ['memberuser']
    member_count_out = (
        _('%i user or group added.'),
        _('%i users or groups added.'))

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(entry_attrs, 'usercategory'):
            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be added when user category='all'"))
        return dn


@register()
class caacl_remove_user(LDAPRemoveMember):
    __doc__ = _('Remove users and groups from a CA ACL.')

    member_attributes = ['memberuser']
    member_count_out = (
        _('%i user or group removed.'),
        _('%i users or groups removed.'))


@register()
class caacl_add_host(LDAPAddMember):
    __doc__ = _('Add target hosts and hostgroups to a CA ACL.')

    member_attributes = ['memberhost']
    member_count_out = (
        _('%i host or hostgroup added.'),
        _('%i hosts or hostgroups added.'))

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(entry_attrs, 'hostcategory'):
            raise errors.MutuallyExclusiveError(
                reason=_("hosts cannot be added when host category='all'"))
        return dn


@register()
class caacl_remove_host(LDAPRemoveMember):
    __doc__ = _('Remove target hosts and hostgroups from a CA ACL.')

    member_attributes = ['memberhost']
    member_count_out = (
        _('%i host or hostgroup removed.'),
        _('%i hosts or hostgroups removed.'))


@register()
class caacl_add_service(LDAPAddMember):
    __doc__ = _('Add services to a CA ACL.')

    member_attributes = ['memberservice']
    member_count_out = (_('%i service added.'), _('%i services added.'))

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(entry_attrs, 'servicecategory'):
            raise errors.MutuallyExclusiveError(reason=_(
                "services cannot be added when service category='all'"))
        return dn


@register()
class caacl_remove_service(LDAPRemoveMember):
    __doc__ = _('Remove services from a CA ACL.')

    member_attributes = ['memberservice']
    member_count_out = (_('%i service removed.'), _('%i services removed.'))


caacl_output_params = global_output_params + (
    Str('ipamembercertprofile',
        label=_('Failed profiles'),
    ),
    # Commented until caacl plugin arrives
    #Str('ipamemberca',
    #    label=_('Failed CAs'),
    #),
)


@register()
class caacl_add_profile(LDAPAddMember):
    __doc__ = _('Add profiles to a CA ACL.')

    has_output_params = caacl_output_params

    member_attributes = ['ipamembercertprofile']
    member_count_out = (_('%i profile added.'), _('%i profiles added.'))

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if is_all(entry_attrs, 'ipacertprofilecategory'):
            raise errors.MutuallyExclusiveError(reason=_(
                "profiles cannot be added when profile category='all'"))
        return dn


@register()
class caacl_remove_profile(LDAPRemoveMember):
    __doc__ = _('Remove profiles from a CA ACL.')

    has_output_params = caacl_output_params

    member_attributes = ['ipamembercertprofile']
    member_count_out = (_('%i profile removed.'), _('%i profiles removed.'))
