# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#   Adam Young <ayoung@redhat.com>
#   Endi S. Dewata <edewata@redhat.com>
#
# Copyright (c) 2010  Red Hat
# See file 'copying' for use and warranty information
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

"""
Plugins not accessible directly through the CLI, commands used internally
"""

import json

from ipalib import api
from ipalib import Command
from ipalib import Str
from ipalib.output import Output
from ipalib.text import _
from ipalib.util import json_serialize
from ipalib.plugable import Registry

register = Registry()

@register()
class json_metadata(Command):
    """
    Export plugin meta-data for the webUI.
    """
    NO_CLI = True


    takes_args = (
        Str('objname?',
            doc=_('Name of object to export'),
        ),
        Str('methodname?',
            doc=_('Name of method to export'),
        ),
    )

    takes_options = (
        Str('object?',
            doc=_('Name of object to export'),
        ),
        Str('method?',
            doc=_('Name of method to export'),
        ),
        Str('command?',
            doc=_('Name of command to export'),
        ),
    )

    has_output = (
        Output('objects', dict, doc=_('Dict of JSON encoded IPA Objects')),
        Output('methods', dict, doc=_('Dict of JSON encoded IPA Methods')),
        Output('commands', dict, doc=_('Dict of JSON encoded IPA Commands')),
    )

    def execute(self, objname, methodname, **options):
        objects = dict()
        methods = dict()
        commands = dict()

        empty = True

        try:
            if not objname:
                objname = options['object']
            if objname in self.api.Object:
                o = self.api.Object[objname]
                objects = dict([(o.name, json_serialize(o))])
            elif objname == "all":
                objects = dict(
                    (o.name, json_serialize(o)) for o in self.api.Object()
                )
            empty = False
        except KeyError:
            pass

        try:
            if not methodname:
                methodname = options['method']
            if methodname in self.api.Method:
                m = self.api.Method[methodname]
                methods = dict([(m.name, json_serialize(m))])
            elif methodname == "all":
                methods = dict(
                    (m.name, json_serialize(m)) for m in self.api.Method()
                )
            empty = False
        except KeyError:
            pass

        try:
            cmdname = options['command']
            if cmdname in self.api.Command:
                c = self.api.Command[cmdname]
                commands = dict([(c.name, json_serialize(c))])
            elif cmdname == "all":
                commands = dict(
                    (c.name, json_serialize(c)) for c in self.api.Command()
                )
            empty = False
        except KeyError:
            pass

        if empty:
            objects = dict(
                (o.name, json_serialize(o)) for o in self.api.Object()
            )
            methods = dict(
                (m.name, json_serialize(m)) for m in self.api.Method()
            )
            commands = dict(
                (c.name, json_serialize(c)) for c in self.api.Command()
            )

        retval = dict([
            ("objects", objects),
            ("methods", methods),
            ("commands", commands),
        ])

        return retval

    def output_for_cli(self, textui, result, *args, **options):
        print json.dumps(result, default=json_serialize)


@register()
class i18n_messages(Command):
    NO_CLI = True

    messages = {
        "ajax": {
            "401": {
                "message": _("Your session has expired. Please re-login."),
            },
        },
        "actions": {
            "apply": _("Apply"),
            "automember_rebuild": _("Rebuild auto membership"),
            "automember_rebuild_confirm": _("Are you sure you want to rebuild auto membership?"),
            "automember_rebuild_success": _("Automember rebuild membership task completed"),
            "confirm": _("Are you sure you want to proceed with the action?"),
            "delete_confirm": _("Are you sure you want to delete ${object}?"),
            "disable_confirm": _("Are you sure you want to disable ${object}?"),
            "enable_confirm": _("Are you sure you want to enable ${object}?"),
            "title": _("Actions"),
        },
        "association": {
            "add": {
                "ipasudorunas": _("Add RunAs ${other_entity} into ${entity} ${primary_key}"),
                "ipasudorunasgroup": _("Add RunAs Groups into ${entity} ${primary_key}"),
                "managedby": _("Add ${other_entity} Managing ${entity} ${primary_key}"),
                "member": _("Add ${other_entity} into ${entity} ${primary_key}"),
                "memberallowcmd": _("Add Allow ${other_entity} into ${entity} ${primary_key}"),
                "memberdenycmd": _("Add Deny ${other_entity} into ${entity} ${primary_key}"),
                "memberof": _("Add ${entity} ${primary_key} into ${other_entity}"),
            },
            "added": _("${count} item(s) added"),
            "direct_membership": _("Direct Membership"),
            "filter_placeholder": _("Filter available ${other_entity}"),
            "indirect_membership": _("Indirect Membership"),
            "no_entries": _("No entries."),
            "paging": _("Showing ${start} to ${end} of ${total} entries."),
            "remove": {
                "ipasudorunas": _("Remove RunAs ${other_entity} from ${entity} ${primary_key}"),
                "ipasudorunasgroup": _("Remove RunAs Groups from ${entity} ${primary_key}"),
                "managedby": _("Remove ${other_entity} Managing ${entity} ${primary_key}"),
                "member": _("Remove ${other_entity} from ${entity} ${primary_key}"),
                "memberallowcmd": _("Remove Allow ${other_entity} from ${entity} ${primary_key}"),
                "memberdenycmd": _("Remove Deny ${other_entity} from ${entity} ${primary_key}"),
                "memberof": _("Remove ${entity} ${primary_key} from ${other_entity}"),
            },
            "removed": _("${count} item(s) removed"),
            "show_results": _("Show Results"),
        },
        "authtype": {
            "config_tooltip": _("Implicit method (password) will be used if no method is chosen."),
            "type_otp": _("Two factor authentication (password + OTP)"),
            "type_password": _("Password"),
            "type_radius": _("Radius"),
            "type_disabled": _("Disable per-user override"),
            "user_tooltip": _("Per-user setting, overwrites the global setting if any option is checked."),
        },
        "buttons": {
            "about": _("About"),
            "activate": _("Activate"),
            "add": _("Add"),
            "add_and_add_another": _("Add and Add Another"),
            "add_and_close": _("Add and Close"),
            "add_and_edit": _("Add and Edit"),
            "add_many": _("Add Many"),
            "apply": _("Apply"),
            "back": _("Back"),
            "cancel": _("Cancel"),
            "close": _("Close"),
            "disable": _("Disable"),
            "edit": _("Edit"),
            "enable": _("Enable"),
            "filter": _("Filter"),
            "find": _("Find"),
            "get": _("Get"),
            "hide": _("Hide"),
            "issue": _("Issue"),
            "ok": _("OK"),
            "refresh": _("Refresh"),
            "remove": _("Delete"),
            "reset": _("Reset"),
            "reset_password_and_login": _("Reset Password and Login"),
            "restore": _("Restore"),
            "retry": _("Retry"),
            "revert": _("Revert"),
            "revoke": _("Revoke"),
            "save": _("Save"),
            "set": _("Set"),
            "show": _("Show"),
            "unapply": ("Un-apply"),
            "update": _("Update"),
            "view": _("View"),
        },
        "details": {
            "collapse_all": _("Collapse All"),
            "expand_all": _("Expand All"),
            "general": _("General"),
            "identity": _("Identity Settings"),
            "settings": _("${entity} ${primary_key} Settings"),
            "to_top": _("Back to Top"),
            "updated": _("${entity} ${primary_key} updated"),
        },
        "dialogs": {
            "add_confirmation": _("${entity} successfully added"),
            "add_title": _("Add ${entity}"),
            "available": _("Available"),
            "batch_error_message": _("Some operations failed."),
            "batch_error_title": _("Operations Error"),
            "confirmation": _("Confirmation"),
            "dirty_message": _("This page has unsaved changes. Please save or revert."),
            "dirty_title": _("Unsaved Changes"),
            "edit_title": _("Edit ${entity}"),
            "hide_details": _("Hide details"),
            "about_title": _("About"),
            "about_message": _("${product}, version: ${version}"),
            "prospective": _("Prospective"),
            "redirection": _("Redirection"),
            "remove_empty": _("Select entries to be removed."),
            "remove_title": _("Remove ${entity}"),
            "show_details": _("Show details"),
            "success": _("Success"),
            "validation_title": _("Validation error"),
            "validation_message": _("Input form contains invalid or missing values."),
        },
        "error_report": {
            "options": _("Please try the following options:"),
            "problem_persists": _("If the problem persists please contact the system administrator."),
            "refresh": _("Refresh the page."),
            "reload": _("Reload the browser."),
            "main_page": _("Return to the main page and retry the operation"),
            "title": _("An error has occurred (${error})"),
        },
        "errors": {
            "error": _("Error"),
            "http_error": _("HTTP Error"),
            "internal_error": _("Internal Error"),
            "ipa_error": _("IPA Error"),
            "no_response": _("No response"),
            "unknown_error": _("Unknown Error"),
            "url": _("URL"),
        },
        "facet_groups": {
            "managedby": _("${primary_key} is managed by:"),
            "member": _("${primary_key} members:"),
            "memberof": _("${primary_key} is a member of:"),
        },
        "facets": {
            "details": _("Settings"),
            "search": _("Search"),
        },
        "false": _("False"),
        "keytab": {
            "add_create": _("Allow ${other_entity} to create keytab of ${primary_key}"),
            "add_retrive": _("Allow ${other_entity} to retrieve keytab of ${primary_key}"),
            "allowed_to_create": _("Allowed to create keytab"),
            "allowed_to_retrieve": _("Allowed to retrieve keytab"),
            "remove_create": _("Disallow ${other_entity} to create keytab of ${primary_key}"),
            "remove_retrieve": _("Disallow ${other_entity} to retrieve keytab of ${primary_key}"),
        },
        "krbauthzdata": {
            "inherited": _("Inherited from server configuration"),
            "mspac": _("MS-PAC"),
            "override": _("Override inherited settings"),
            "pad": _("PAD"),
        },
        "login": {
            "form_auth": _("<i class=\"fa fa-info-circle\"></i> To login with <strong>username and password</strong>, enter them in the corresponding fields, then click Login."),
            "header": _("Logged In As"),
            "krb_auth_msg": _("<i class=\"fa fa-info-circle\"></i> To login with <strong>Kerberos</strong>, please make sure you have valid tickets (obtainable via kinit) and <a href='http://${host}/ipa/config/unauthorized.html'>configured</a> the browser correctly, then click Login."),
            "login": _("Login"),
            "logout": _("Logout"),
            "logout_error": _("Logout error"),
            "password": _("Password"),
            "sync_otp_token": _("Sync OTP Token"),
            "username": _("Username"),
        },
        "measurement_units": {
            "number_of_passwords": _("number of passwords"),
            "seconds": _("seconds"),
        },
        "objects": {
            "aci": {
                "attribute": _("Attribute"),
            },
            "automember": {
                "add_condition": _("Add Condition into ${pkey}"),
                "add_rule": _("Add Rule"),
                "attribute": _("Attribute"),
                "default_host_group": _("Default host group"),
                "default_user_group": _("Default user group"),
                "exclusive": _("Exclusive"),
                "expression": _("Expression"),
                "hostgrouprule": _("Host group rule"),
                "hostgrouprules": _("Host group rules"),
                "inclusive": _("Inclusive"),
                "usergrouprule": _("User group rule"),
                "usergrouprules": _("User group rules"),
            },
            "automountkey": {
            },
            "automountlocation": {
                "identity": _("Automount Location Settings")
            },
            "automountmap": {
                "map_type": _("Map Type"),
                "direct": _("Direct"),
                "indirect": _("Indirect"),
            },
            "caacl": {
                "any_host": _("Any Host"),
                "any_service": _("Any Service"),
                "any_profile": _("Any Profile"),
                "anyone": _("Anyone"),
                "ipaenabledflag": _("Rule status"),
                "profile": _("Profiles"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_profiles": _("Specified Profiles"),
                "specified_services": _("Specified Services and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "who": _("Permitted to have certificates issued"),
            },
            "cert": {
                "aa_compromise": _("AA Compromise"),
                "add_principal": _("Add principal"),
                "affiliation_changed": _("Affiliation Changed"),
                "ca_compromise": _("CA Compromise"),
                "certificate": _("Certificate"),
                "certificates": _("Certificates"),
                "certificate_hold": _("Certificate Hold"),
                "cessation_of_operation": _("Cessation of Operation"),
                "common_name": _("Common Name"),
                "expires_on": _("Expires On"),
                "find_issuedon_from": _("Issued on from"),
                "find_issuedon_to": _("Issued on to"),
                "find_max_serial_number": _("Maximum serial number"),
                "find_min_serial_number": _("Minimum serial number"),
                "find_revocation_reason": _("Revocation reason"),
                "find_revokedon_from": _("Revoked on from"),
                "find_revokedon_to": _("Revoked on to"),
                "find_subject": _("Subject"),
                "find_validnotafter_from": _("Valid not after from"),
                "find_validnotafter_to": _("Valid not after to"),
                "find_validnotbefore_from": _("Valid not before from"),
                "find_validnotbefore_to": _("Valid not before to"),
                "fingerprints": _("Fingerprints"),
                "get_certificate": _("Get Certificate"),
                "issue_certificate": _("Issue New Certificate for ${entity} ${primary_key}"),
                "issue_certificate_generic": _("Issue New Certificate"),
                "issued_by": _("Issued By"),
                "issued_on": _("Issued On"),
                "issued_to": _("Issued To"),
                "key_compromise": _("Key Compromise"),
                "md5_fingerprint": _("MD5 Fingerprint"),
                "missing": _("No Valid Certificate"),
                "new_certificate": _("New Certificate"),
                "note": _("Note"),
                "organization": _("Organization"),
                "organizational_unit": _("Organizational Unit"),
                "present": _("${count} certificate(s) present"),
                "privilege_withdrawn": _("Privilege Withdrawn"),
                "reason": _("Reason for Revocation"),
                "remove_from_crl": _("Remove from CRL"),
                "request_message": _("<ol> <li>Create a certificate database or use an existing one. To create a new database:<br/> <code># certutil -N -d &lt;database path&gt;</code> </li> <li>Create a CSR with subject <em>CN=&lt;${cn_name}&gt;,O=&lt;realm&gt;</em>, for example:<br/> <code># certutil -R -d &lt;database path&gt; -a -g &lt;key size&gt; -s 'CN=${cn},O=${realm}'</code> </li> <li> Copy and paste the CSR (from <em>-----BEGIN NEW CERTIFICATE REQUEST-----</em> to <em>-----END NEW CERTIFICATE REQUEST-----</em>) into the text area below: </li> </ol>"),
                "requested": _("Certificate requested"),
                "restore_certificate": _("Restore Certificate for ${entity} ${primary_key}"),
                "restore_certificate_simple": _("Restore Certificate"),
                "restore_confirmation": _("To confirm your intention to restore this certificate, click the \"Restore\" button."),
                "restored": _("Certificate restored"),
                "revocation_reason": _("Revocation reason"),
                "revoke_certificate": _("Revoke Certificate for ${entity} ${primary_key}"),
                "revoke_certificate_simple": _("Revoke Certificate"),
                "revoke_confirmation": _("To confirm your intention to revoke this certificate, select a reason from the pull-down list, and click the \"Revoke\" button."),
                "revoked": _("Certificate Revoked"),
                "serial_number": _("Serial Number"),
                "serial_number_hex": _("Serial Number (hex)"),
                "sha1_fingerprint": _("SHA1 Fingerprint"),
                "status": _("Status"),
                "superseded": _("Superseded"),
                "unspecified": _("Unspecified"),
                "valid": _("Valid Certificate Present"),
                "validity": _("Validity"),
                "view_certificate": _("Certificate for ${entity} ${primary_key}"),
                "view_certificate_btn": _("View Certificate"),
            },
            "config": {
                "group": _("Group Options"),
                "search": _("Search Options"),
                "selinux": _("SELinux Options"),
                "service": _("Service Options"),
                "user": _("User Options"),
            },
            "delegation": {
            },
            "dnsconfig": {
                "forward_first": _("Forward first"),
                "forward_none": _("Forwarding disabled"),
                "forward_only": _("Forward only"),
                "options": _("Options"),
            },
            "dnsrecord": {
                "data": _("Data"),
                "deleted_no_data": _("DNS record was deleted because it contained no data."),
                "other": _("Other Record Types"),
                "ptr_redir_address_err": _("Address not valid, can't redirect"),
                "ptr_redir_create": _("Create dns record"),
                "ptr_redir_creating": _("Creating record."),
                "ptr_redir_creating_err": _("Record creation failed."),
                "ptr_redir_record": _("Checking if record exists."),
                "ptr_redir_record_err": _("Record not found."),
                "ptr_redir_title": _("Redirection to PTR record"),
                "ptr_redir_zone": _("Zone found: ${zone}"),
                "ptr_redir_zone_err": _("Target reverse zone not found."),
                "ptr_redir_zones": _("Fetching DNS zones."),
                "ptr_redir_zones_err": _("An error occurred while fetching dns zones."),
                "redirection_dnszone": _("You will be redirected to DNS Zone."),
                "standard": _("Standard Record Types"),
                "title": _("Records for DNS Zone"),
                "type": _("Record Type"),
            },
            "dnszone": {
                "identity": _("DNS Zone Settings"),
                "add_permission":_("Add Permission"),
                "add_permission_confirm":_("Are you sure you want to add permission for DNS Zone ${object}?"),
                "remove_permission": _("Remove Permission"),
                "remove_permission_confirm": _("Are you sure you want to remove permission for DNS Zone ${object}?"),
                "skip_dns_check": _("Skip DNS check"),
                "soamname_change_message": _("Do you want to check if new authoritative nameserver address is in DNS"),
                "soamname_change_title": _("Authoritative nameserver change"),
            },
            "domainlevel": {
                "label": _("Domain Level"),
                "label_singular": _("Domain Level"),
                "ipadomainlevel": _("Level"),
                "set": _("Set Domain Level"),
            },
            "group": {
                "details": _("Group Settings"),
                "external": _("External"),
                "make_external": _("Change to external group"),
                "make_posix": _("Change to POSIX group"),
                "normal": _("Normal"),
                "posix": _("POSIX"),
                "type": _("Group Type"),
            },
            "hbacrule": {
                "any_host": _("Any Host"),
                "any_service": _("Any Service"),
                "anyone": _("Anyone"),
                "host": _("Accessing"),
                "ipaenabledflag": _("Rule status"),
                "service": _("Via Service"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_services": _("Specified Services and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("Who"),
            },
            "hbacsvc": {
            },
            "hbacsvcgroup": {
                "services": _("Services"),
            },
            "hbactest": {
                "access_denied": _("Access Denied"),
                "access_granted": _("Access Granted"),
                "include_disabled": _("Include Disabled"),
                "include_enabled": _("Include Enabled"),
                "label": _("HBAC Test"),
                "matched": _("Matched"),
                "missing_values": _("Missing values: "),
                "new_test": _("New Test"),
                "rules": _("Rules"),
                "run_test": _("Run Test"),
                "specify_external": _("Specify external ${entity}"),
                "unmatched": _("Unmatched"),
            },
            "host": {
                "certificate": _("Host Certificate"),
                "cn": _("Host Name"),
                "delete_key_unprovision": _("Delete Key, Unprovision"),
                "details": _("Host Settings"),
                "enrolled": _("Enrolled"),
                "enrollment": _("Enrollment"),
                "fqdn": _("Fully Qualified Host Name"),
                "keytab": _("Kerberos Key"),
                "keytab_missing": _("Kerberos Key Not Present"),
                "keytab_present": _("Kerberos Key Present, Host Provisioned"),
                "password": _("One-Time-Password"),
                "password_missing": _("One-Time-Password Not Present"),
                "password_present": _("One-Time-Password Present"),
                "password_reset_button": _("Reset OTP"),
                "password_reset_title": _("Reset One-Time-Password"),
                "password_set_button": _("Set OTP"),
                "password_set_success": _("OTP set"),
                "password_set_title": _("Set One-Time-Password"),
                "status": _("Status"),
                "unprovision": _("Unprovision"),
                "unprovision_confirmation": _("Are you sure you want to unprovision this host?"),
                "unprovision_title": _("Unprovisioning ${entity}"),
                "unprovisioned": _("Host unprovisioned"),
            },
            "hostgroup": {
                "identity": _("Host Group Settings"),
            },
            "idoverrideuser": {
                "anchor_label": _("User to override"),
                "anchor_tooltip": _("Enter trusted or IPA user login. Note: search doesn't list users from trusted domains."),
                "anchor_tooltip_ad": _("Enter trusted user login."),
            },
            "idoverridegroup": {
                "anchor_label": _("Group to override"),
                "anchor_tooltip": _("Enter trusted or IPA group name. Note: search doesn't list groups from trusted domains."),
                "anchor_tooltip_ad": _("Enter trusted group name."),
            },
            "idview": {
                "appliesto_tab": _("${primary_key} applies to:"),
                "appliedtohosts": _("Applied to hosts"),
                "appliedtohosts_title": _("Applied to hosts"),
                "apply_hostgroups": _("Apply to host groups"),
                "apply_hostgroups_title": _("Apply ID View ${primary_key} on hosts of ${entity}"),
                "apply_hosts": _("Apply to hosts"),
                "apply_hosts_title": _("Apply ID view ${primary_key} on ${entity}"),
                "ipaassignedidview": _("Assigned ID View"),
                "overrides_tab": _("${primary_key} overrides:"),
                "unapply_hostgroups": _("Un-apply from host groups"),
                "unapply_hostgroups_all_title": _("Un-apply ID Views from hosts of hostgroups"),
                "unapply_hostgroups_title": _("Un-apply ID View ${primary_key} from hosts of ${entity}"),
                "unapply_hosts": _("Un-apply"),
                "unapply_hosts_all": _("Un-apply from hosts"),
                "unapply_hosts_all_title": _("Un-apply ID Views from hosts"),
                "unapply_hosts_confirm": _("Are you sure you want to un-apply ID view from selected entries?"),
                "unapply_hosts_title": _("Un-apply ID View ${primary_key} from hosts"),
            },
            "krbtpolicy": {
                "identity": _("Kerberos Ticket Policy"),
            },
            "netgroup": {
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "external": _("External"),
                "host": _("Host"),
                "hostgroups": _("Host Groups"),
                "hosts": _("Hosts"),
                "identity": _("Netgroup Settings"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("User"),
                "usergroups": _("User Groups"),
                "users": _("Users"),
            },
            "otptoken": {
                "add_token": _("Add OTP Token"),
                "app_link": _("You can use <a href=\"${link}\" target=\"_blank\">FreeOTP<a/> as a software OTP token application."),
                "config_title": _("Configure your token"),
                "config_instructions": _("Configure your token by scanning the QR code below. Click on the QR code if you see this on the device you want to configure."),
                "details": _("OTP Token Settings"),
                "disable": _("Disable token"),
                "enable": _("Enable token"),
                "show_qr": _("Show QR code"),
                "show_uri": _("Show configuration uri"),
                "type_hotp": _("Counter-based (HOTP)"),
                "type_totp": _("Time-based (TOTP)"),
            },
            "permission": {
                "add_custom_attr": _("Add custom attribute"),
                "attribute": _("Attribute"),
                "filter": _("Filter"),
                "identity": _("Permission settings"),
                "managed": _("Attribute breakdown"),
                "target": _("Target"),
            },
            "privilege": {
                "identity": _("Privilege Settings"),
            },
            "pwpolicy": {
                "identity": _("Password Policy"),
            },
            "idrange": {
                "details": _("Range Settings"),
                "ipabaseid": _("Base ID"),
                "ipabaserid": _("Primary RID base"),
                "ipaidrangesize": _("Range size"),
                "ipanttrusteddomainsid": _("Domain SID"),
                "ipasecondarybaserid": _("Secondary RID base"),
                "type": _("Range type"),
                "type_ad": _("Active Directory domain"),
                "type_ad_posix": _("Active Directory domain with POSIX attributes"),
                "type_detect": _("Detect"),
                "type_local": _("Local domain"),
                "type_ipa": _("IPA trust"),
                "type_winsync": _("Active Directory winsync"),
            },
            "radiusproxy": {
                "details": _("RADIUS Proxy Server Settings"),
            },
            "realmdomains": {
                "identity": _("Realm Domains"),
                "check_dns": _("Check DNS"),
                "check_dns_confirmation": _("Do you also want to perform DNS check?"),
                "force_update": _("Force Update"),
            },
            "role": {
                "identity": _("Role Settings"),
            },
            "selfservice": {
            },
            "selinuxusermap": {
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "host": _("Host"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("User"),
            },
            "service": {
                "certificate": _("Service Certificate"),
                "delete_key_unprovision": _("Delete Key, Unprovision"),
                "details": _("Service Settings"),
                "host": _("Host Name"),
                "missing": _("Kerberos Key Not Present"),
                "provisioning": _("Provisioning"),
                "service": _("Service"),
                "status": _("Status"),
                "unprovision": _("Unprovision"),
                "unprovision_confirmation": _("Are you sure you want to unprovision this service?"),
                "unprovision_title": _("Unprovisioning ${entity}"),
                "unprovisioned": _("Service unprovisioned"),
                "valid": _("Kerberos Key Present, Service Provisioned"),
            },
            "sshkeystore": {
                "keys": _("SSH public keys"),
                "set_dialog_help": _("SSH public key:"),
                "set_dialog_title": _("Set SSH key"),
                "show_set_key": _("Show/Set key"),
                "status_mod_ns": _("Modified: key not set"),
                "status_mod_s": _("Modified"),
                "status_new_ns": _("New: key not set"),
                "status_new_s": _("New: key set"),
            },
            "stageuser": {
                "activate_confirm": _("Are you sure you want to activate selected users?"),
                "activate_success": _("${count} user(s) activated"),
                "label": _("Stage users"),
                "preserved_label": _("Preserved users"),
                "undel_confirm": _("Are you sure you want to restore selected users?"),
                "undel_success": _("${count} user(s) restored"),
                "user_categories": _("User categories"),
            },
            "sudocmd": {
                "groups": _("Groups"),
            },
            "sudocmdgroup": {
                "commands": _("Commands"),
            },
            "sudorule": {
                "allow": _("Allow"),
                "any_command": _("Any Command"),
                "any_group": _("Any Group"),
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "command": _("Run Commands"),
                "deny": _("Deny"),
                "external": _("External"),
                "host": _("Access this host"),
                "ipaenabledflag": _("Rule status"),
                "option_added": _("Option added"),
                "option_removed": _("${count} option(s) removed"),
                "options": _("Options"),
                "runas": _("As Whom"),
                "specified_commands": _("Specified Commands and Groups"),
                "specified_groups": _("Specified Groups"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("Who"),
            },
            "topology": {
                "segment_details": _("Segment details"),
                "replication_config": _("Replication configuration"),
            },
            "trust": {
                "account": _("Account"),
                "admin_account": _("Administrative account"),
                "blacklists": _("SID blacklists"),
                "details": _("Trust Settings"),
                "domain": _("Domain"),
                "establish_using": _("Establish using"),
                "fetch_domains": _("Fetch domains"),
                "ipantflatname": _("Domain NetBIOS name"),
                "ipanttrusteddomainsid": _("Domain Security Identifier"),
                "preshared_password": _("Pre-shared password"),
                "trustdirection": _("Trust direction"),
                "truststatus": _("Trust status"),
                "trusttype": _("Trust type"),
            },
            "trustconfig": {
                "options": _("Options"),
            },
            "user": {
                "account": _("Account Settings"),
                "account_status": _("Account Status"),
                "activeuser_label": _("Active users"),
                "contact": _("Contact Settings"),
                "delete_mode": _("Delete mode"),
                "employee": _("Employee Information"),
                "error_changing_status": _("Error changing account status"),
                "krbpasswordexpiration": _("Password expiration"),
                "mailing": _("Mailing Address"),
                "misc": _("Misc. Information"),
                "mode_delete": _("delete"),
                "mode_preserve": _("preserve"),
                "noprivate": _("No private group"),
                "status_confirmation": _("Are you sure you want to ${action} the user?<br/>The change will take effect immediately."),
                "status_link": _("Click to ${action}"),
                "unlock": _("Unlock"),
                "unlock_confirm": _("Are you sure you want to unlock user ${object}?"),
            },
        },
        "password": {
            "current_password": _("Current Password"),
            "current_password_required": _("Current password is required"),
            "expires_in": _("Your password expires in ${days} days."),
            "first_otp": _("First OTP"),
            "invalid_password": _("The password or username you entered is incorrect."),
            "new_password": _("New Password"),
            "new_password_required": _("New password is required"),
            "otp": _("OTP"),
            "otp_info": _("<i class=\"fa fa-info-circle\"></i> <strong>One-Time-Password(OTP):</strong> Generate new OTP code for each OTP field."),
            "otp_long": _("One-Time-Password"),
            "otp_sync_fail": _("Token synchronization failed"),
            "otp_sync_invalid": _("The username, password or token codes are not correct"),
            "otp_sync_success":_("Token was synchronized"),
            "password": _("Password"),
            "password_and_otp": _("Password or Password+One-Time-Password"),
            "password_change_complete": _("Password change complete"),
            "password_must_match": _("Passwords must match"),
            "reset_failure": _("Password reset was not successful."),
            "reset_password": _("Reset Password"),
            "reset_password_sentence": _("Reset your password."),
            "second_otp": _("Second OTP"),
            "token_id": _("Token ID"),
            "verify_password": _("Verify Password"),
        },
        "search": {
            "delete_confirm": _("Are you sure you want to delete selected entries?"),
            "deleted": _("${count} item(s) deleted"),
            "disable_confirm": _("Are you sure you want to disable selected entries?"),
            "disabled": _("${count} item(s) disabled"),
            "enable_confirm": _("Are you sure you want to enable selected entries?"),
            "enabled": _("${count} item(s) enabled"),
            "partial_delete": _("Some entries were not deleted"),
            "placeholder": _("Search"),
            "quick_links": _("Quick Links"),
            "select_all": _("Select All"),
            "truncated": _("Query returned more results than the configured size limit. Displaying the first ${counter} results."),
            "unselect_all": _("Unselect All"),
        },
        "status": {
            "disable": _("Disable"),
            "disabled": _("Disabled"),
            "enable": _("Enable"),
            "enabled": _("Enabled"),
            "label": _("Status"),
            "working": _("Working"),
        },
        "tabs": {
            "audit": _("Audit"),
            "authentication": _("Authentication"),
            "automember": _("Automember"),
            "automount": _("Automount"),
            "cert": _("Certificates"),
            "dns": _("DNS"),
            "hbac": _("Host Based Access Control"),
            "identity": _("Identity"),
            "ipaserver": _("IPA Server"),
            "network_services": _("Network Services"),
            "policy": _("Policy"),
            "role": _("Role Based Access Control"),
            "sudo": _("Sudo"),
            "topology": _("Topology"),
            "trust": _("Trusts"),
        },
        "true": _("True"),
        "widget": {
            "first": _("First"),
            "last": _("Last"),
            "next": _("Next"),
            "page": _("Page"),
            "prev": _("Prev"),
            "undo": _("Undo"),
            "undo_all": _("Undo All"),
            "validation": {
                "error": _("Text does not match field pattern"),
                "datetime": _("Must be an UTC date/time value (e.g., \"2014-01-20 17:58:01Z\")"),
                "decimal": _("Must be a decimal number"),
                "format": _("Format error"),
                "integer": _("Must be an integer"),
                "ip_address": _('Not a valid IP address'),
                "ip_v4_address": _('Not a valid IPv4 address'),
                "ip_v6_address": _('Not a valid IPv6 address'),
                "max_value": _("Maximum value is ${value}"),
                "min_value": _("Minimum value is ${value}"),
                "net_address": _("Not a valid network address"),
                "parse": _("Parse error"),
                "port": _("'${port}' is not a valid port"),
                "required": _("Required field"),
                "unsupported": _("Unsupported value"),
            },
        },
    }
    has_output = (
        Output('texts', dict, doc=_('Dict of I18N messages')),
    )
    def execute(self, **options):
        return dict(texts=json_serialize(self.messages))

    def output_for_cli(self, textui, result, *args, **options):
        print json.dumps(result, default=json_serialize)


