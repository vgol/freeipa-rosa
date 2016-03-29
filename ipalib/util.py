# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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

"""
Various utility functions.
"""

import os
import imp
import time
import socket
import re
import decimal
import dns
import encodings
import netaddr
from types import NoneType
from weakref import WeakKeyDictionary
from dns import resolver, rdatatype
from dns.exception import DNSException
from dns.resolver import NXDOMAIN
from netaddr.core import AddrFormatError

from ipalib import errors, messages
from ipalib.text import _
from ipapython.ssh import SSHPublicKey
from ipapython.dn import DN, RDN
from ipapython.dnsutil import DNSName
from ipapython.graph import Graph


def json_serialize(obj):
    if isinstance(obj, (list, tuple)):
        return [json_serialize(o) for o in obj]
    if isinstance(obj, dict):
        return dict((k, json_serialize(v)) for (k, v) in obj.iteritems())
    if isinstance(obj, (bool, float, int, long, unicode, NoneType)):
        return obj
    if isinstance(obj, str):
        return obj.decode('utf-8')
    if isinstance(obj, (decimal.Decimal, DN)):
        return str(obj)
    if not callable(getattr(obj, '__json__', None)):
        # raise TypeError('%r is not JSON serializable')
        return ''
    return json_serialize(obj.__json__())

def get_current_principal():
    try:
        import kerberos
        rc, vc = kerberos.authGSSClientInit("notempty")
        rc = kerberos.authGSSClientInquireCred(vc)
        username = kerberos.authGSSClientUserName(vc)
        kerberos.authGSSClientClean(vc)
        return unicode(username)
    except ImportError:
        raise RuntimeError('python-kerberos is not available.')
    except kerberos.GSSError, e:
        #TODO: do a kinit?
        raise errors.CCacheError()


def validate_host_dns(log, fqdn):
    """
    See if the hostname has a DNS A/AAAA record.
    """
    try:
        answers = resolver.query(fqdn, rdatatype.A)
        log.debug(
            'IPA: found %d A records for %s: %s' % (len(answers), fqdn,
                ' '.join(str(answer) for answer in answers))
        )
    except DNSException, e:
        log.debug(
            'IPA: DNS A record lookup failed for %s' % fqdn
        )
        # A record not found, try to find AAAA record
        try:
            answers = resolver.query(fqdn, rdatatype.AAAA)
            log.debug(
                'IPA: found %d AAAA records for %s: %s' % (len(answers), fqdn,
                    ' '.join(str(answer) for answer in answers))
            )
        except DNSException, e:
            log.debug(
                'IPA: DNS AAAA record lookup failed for %s' % fqdn
            )
            raise errors.DNSNotARecordError()


def has_soa_or_ns_record(domain):
    """
    Checks to see if given domain has SOA or NS record.
    Returns True or False.
    """
    try:
        resolver.query(domain, rdatatype.SOA)
        soa_record_found = True
    except DNSException:
        soa_record_found = False

    try:
        resolver.query(domain, rdatatype.NS)
        ns_record_found = True
    except DNSException:
        ns_record_found = False

    return soa_record_found or ns_record_found


def normalize_name(name):
    result = dict()
    components = name.split('@')
    if len(components) == 2:
        result['domain'] = unicode(components[1]).lower()
        result['name'] = unicode(components[0]).lower()
    else:
        components = name.split('\\')
        if len(components) == 2:
            result['flatname'] = unicode(components[0]).lower()
            result['name'] = unicode(components[1]).lower()
        else:
            result['name'] = unicode(name).lower()
    return result

def isvalid_base64(data):
    """
    Validate the incoming data as valid base64 data or not.

    The character set must only include of a-z, A-Z, 0-9, + or / and
    be padded with = to be a length divisible by 4 (so only 0-2 =s are
    allowed). Its length must be divisible by 4. White space is
    not significant so it is removed.

    This doesn't guarantee we have a base64-encoded value, just that it
    fits the base64 requirements.
    """

    data = ''.join(data.split())

    if len(data) % 4 > 0 or \
        re.match('^[a-zA-Z0-9\+\/]+\={0,2}$', data) is None:
        return False
    else:
        return True

def validate_ipaddr(ipaddr):
    """
    Check to see if the given IP address is a valid IPv4 or IPv6 address.

    Returns True or False
    """
    try:
        socket.inet_pton(socket.AF_INET, ipaddr)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ipaddr)
        except socket.error:
            return False
    return True

def check_writable_file(filename):
    """
    Determine if the file is writable. If the file doesn't exist then
    open the file to test writability.
    """
    if filename is None:
        raise errors.FileError(reason=_('Filename is empty'))
    try:
        if os.path.exists(filename):
            if not os.access(filename, os.W_OK):
                raise errors.FileError(reason=_('Permission denied: %(file)s') % dict(file=filename))
        else:
            fp = open(filename, 'w')
            fp.close()
    except (IOError, OSError), e:
        raise errors.FileError(reason=str(e))

def normalize_zonemgr(zonemgr):
    if not zonemgr or not isinstance(zonemgr, basestring):
        return zonemgr
    if '@' in zonemgr:
        # local-part needs to be normalized
        name, at, domain = zonemgr.partition('@')
        name = name.replace('.', '\\.')
        zonemgr = u''.join((name, u'.', domain))

    return zonemgr

def normalize_zone(zone):
    if zone[-1] != '.':
        return zone + '.'
    else:
        return zone


def validate_dns_label(dns_label, allow_underscore=False, allow_slash=False):
    base_chars = 'a-z0-9'
    extra_chars = ''
    middle_chars = ''

    if allow_underscore:
        extra_chars += '_'
    if allow_slash:
        middle_chars += '/'

    middle_chars = middle_chars + '-' #has to be always the last in the regex [....-]

    label_regex = r'^[%(base)s%(extra)s]([%(base)s%(extra)s%(middle)s]?[%(base)s%(extra)s])*$' \
        % dict(base=base_chars, extra=extra_chars, middle=middle_chars)
    regex = re.compile(label_regex, re.IGNORECASE)

    if not dns_label:
        raise ValueError(_('empty DNS label'))

    if len(dns_label) > 63:
        raise ValueError(_('DNS label cannot be longer that 63 characters'))

    if not regex.match(dns_label):
        chars = ', '.join("'%s'" % c for c in extra_chars + middle_chars)
        chars2 = ', '.join("'%s'" % c for c in middle_chars)
        raise ValueError(_("only letters, numbers, %(chars)s are allowed. " \
                           "DNS label may not start or end with %(chars2)s") \
                           % dict(chars=chars, chars2=chars2))


def validate_domain_name(domain_name, allow_underscore=False, allow_slash=False):
    if domain_name.endswith('.'):
        domain_name = domain_name[:-1]

    domain_name = domain_name.split(".")

    # apply DNS name validator to every name part
    map(lambda label:validate_dns_label(label, allow_underscore, allow_slash), domain_name)


def validate_zonemgr(zonemgr):
    assert isinstance(zonemgr, DNSName)
    if any('@' in label for label in zonemgr.labels):
        raise ValueError(_('too many \'@\' characters'))


def validate_zonemgr_str(zonemgr):
    zonemgr = normalize_zonemgr(zonemgr)
    validate_idna_domain(zonemgr)
    zonemgr = DNSName(zonemgr)
    return validate_zonemgr(zonemgr)

def validate_hostname(hostname, check_fqdn=True, allow_underscore=False, allow_slash=False):
    """ See RFC 952, 1123

    :param hostname Checked value
    :param check_fqdn Check if hostname is fully qualified
    """
    if len(hostname) > 255:
        raise ValueError(_('cannot be longer that 255 characters'))

    if hostname.endswith('.'):
        hostname = hostname[:-1]

    if '..' in hostname:
        raise ValueError(_('hostname contains empty label (consecutive dots)'))

    if '.' not in hostname:
        if check_fqdn:
            raise ValueError(_('not fully qualified'))
        validate_dns_label(hostname, allow_underscore, allow_slash)
    else:
        validate_domain_name(hostname, allow_underscore, allow_slash)

def normalize_sshpubkey(value):
    return SSHPublicKey(value).openssh()

def validate_sshpubkey(ugettext, value):
    try:
        SSHPublicKey(value)
    except ValueError, UnicodeDecodeError:
        return _('invalid SSH public key')

def validate_sshpubkey_no_options(ugettext, value):
    try:
        pubkey = SSHPublicKey(value)
    except ValueError, UnicodeDecodeError:
        return _('invalid SSH public key')

    if pubkey.has_options():
        return _('options are not allowed')

def convert_sshpubkey_post(ldap, dn, entry_attrs):
    if 'ipasshpubkey' in entry_attrs:
        pubkeys = entry_attrs['ipasshpubkey']
    else:
        old_entry_attrs = ldap.get_entry(dn, ['ipasshpubkey'])
        pubkeys = old_entry_attrs.get('ipasshpubkey')
    if not pubkeys:
        return

    newpubkeys = []
    fingerprints = []
    for pubkey in pubkeys:
        try:
            pubkey = SSHPublicKey(pubkey)
        except ValueError, UnicodeDecodeError:
            continue

        fp = pubkey.fingerprint_hex_md5()
        comment = pubkey.comment()
        if comment:
            fp = u'%s %s' % (fp, comment)
        fp = u'%s (%s)' % (fp, pubkey.keytype())

        newpubkeys.append(pubkey.openssh())
        fingerprints.append(fp)

    if 'ipasshpubkey' in entry_attrs:
        entry_attrs['ipasshpubkey'] = newpubkeys or None
    if fingerprints:
        entry_attrs['sshpubkeyfp'] = fingerprints

class cachedproperty(object):
    """
    A property-like attribute that caches the return value of a method call.

    When the attribute is first read, the method is called and its return
    value is saved and returned. On subsequent reads, the saved value is
    returned.

    Typical usage:
    class C(object):
        @cachedproperty
        def attr(self):
            return 'value'
    """
    __slots__ = ('getter', 'store')

    def __init__(self, getter):
        self.getter = getter
        self.store = WeakKeyDictionary()

    def __get__(self, obj, cls):
        if obj is None:
            return None
        if obj not in self.store:
            self.store[obj] = self.getter(obj)
        return self.store[obj]

    def __set__(self, obj, value):
        raise AttributeError("can't set attribute")

    def __delete__(self, obj):
        raise AttributeError("can't delete attribute")

# regexp matching signed floating point number (group 1) followed by
# optional whitespace followed by time unit, e.g. day, hour (group 7)
time_duration_re = re.compile(r'([-+]?((\d+)|(\d+\.\d+)|(\.\d+)|(\d+\.)))\s*([a-z]+)', re.IGNORECASE)

# number of seconds in a time unit
time_duration_units = {
    'year'    : 365*24*60*60,
    'years'   : 365*24*60*60,
    'y'       : 365*24*60*60,
    'month'   : 30*24*60*60,
    'months'  : 30*24*60*60,
    'week'    : 7*24*60*60,
    'weeks'   : 7*24*60*60,
    'w'       : 7*24*60*60,
    'day'     : 24*60*60,
    'days'    : 24*60*60,
    'd'       : 24*60*60,
    'hour'    : 60*60,
    'hours'   : 60*60,
    'h'       : 60*60,
    'minute'  : 60,
    'minutes' : 60,
    'min'     : 60,
    'second'  : 1,
    'seconds' : 1,
    'sec'     : 1,
    's'       : 1,
}

def parse_time_duration(value):
    '''

    Given a time duration string, parse it and return the total number
    of seconds represented as a floating point value. Negative values
    are permitted.

    The string should be composed of one or more numbers followed by a
    time unit. Whitespace and punctuation is optional. The numbers may
    be optionally signed.  The time units are case insenstive except
    for the single character 'M' or 'm' which means month and minute
    respectively.

    Recognized time units are:

        * year, years, y
        * month, months, M
        * week, weeks, w
        * day, days, d
        * hour, hours, h
        * minute, minutes, min, m
        * second, seconds, sec, s

    Examples:
        "1h"                    # 1 hour
        "2 HOURS, 30 Minutes"   # 2.5 hours
        "1week -1 day"          # 6 days
        ".5day"                 # 12 hours
        "2M"                    # 2 months
        "1h:15m"                # 1.25 hours
        "1h, -15min"            # 45 minutes
        "30 seconds"            # .5 minute

    Note: Despite the appearance you can perform arithmetic the
    parsing is much simpler, the parser searches for signed values and
    adds the signed value to a running total. Only + and - are permitted
    and must appear prior to a digit.

    :parameters:
        value : string
            A time duration string in the specified format
    :returns:
        total number of seconds as float (may be negative)
    '''

    matches = 0
    duration = 0.0
    for match in time_duration_re.finditer(value):
        matches += 1
        magnitude = match.group(1)
        unit = match.group(7)

        # Get the unit, only M and m are case sensitive
        if unit == 'M':         # month
            seconds_per_unit = 30*24*60*60
        elif unit == 'm':       # minute
            seconds_per_unit = 60
        else:
            unit = unit.lower()
            seconds_per_unit = time_duration_units.get(unit)
            if seconds_per_unit is None:
                raise ValueError('unknown time duration unit "%s"' % unit)
        magnitude = float(magnitude)
        seconds = magnitude * seconds_per_unit
        duration += seconds

    if matches == 0:
        raise ValueError('no time duration found in "%s"' % value)

    return duration

def get_dns_forward_zone_update_policy(realm, rrtypes=('A', 'AAAA', 'SSHFP')):
    """
    Generate update policy for a forward DNS zone (idnsUpdatePolicy
    attribute). Bind uses this policy to grant/reject access for client
    machines trying to dynamically update their records.

    :param realm: A realm of the of the client
    :param rrtypes: A list of resource records types that client shall be
                    allowed to update
    """
    policy_element = "grant %(realm)s krb5-self * %(rrtype)s"
    policies = [ policy_element % dict(realm=realm, rrtype=rrtype) \
               for rrtype in rrtypes ]
    policy = "; ".join(policies)
    policy += ";"

    return policy

def get_dns_reverse_zone_update_policy(realm, reverse_zone, rrtypes=('PTR',)):
    """
    Generate update policy for a reverse DNS zone (idnsUpdatePolicy
    attribute). Bind uses this policy to grant/reject access for client
    machines trying to dynamically update their records.

    :param realm: A realm of the of the client
    :param reverse_zone: Name of the actual zone. All clients with IPs in this
                         sub-domain will be allowed to perform changes
    :param rrtypes: A list of resource records types that client shall be
                    allowed to update
    """
    policy_element = "grant %(realm)s krb5-subdomain %(zone)s %(rrtype)s"
    policies = [ policy_element \
                    % dict(realm=realm, zone=reverse_zone, rrtype=rrtype) \
                 for rrtype in rrtypes ]
    policy = "; ".join(policies)
    policy += ";"

    return policy

# dictionary of valid reverse zone -> number of address components
REVERSE_DNS_ZONES = {
    DNSName.ip4_rev_zone : 4,
    DNSName.ip6_rev_zone : 32,
}

def zone_is_reverse(zone_name):
    return DNSName(zone_name).is_reverse()

def get_reverse_zone_default(ip_address):
    ip = netaddr.IPAddress(str(ip_address))
    items = ip.reverse_dns.split('.')

    if ip.version == 4:
        items = items[1:]   # /24 for IPv4
    elif ip.version == 6:
        items = items[16:]  # /64 for IPv6

    return normalize_zone('.'.join(items))

def validate_rdn_param(ugettext, value):
    try:
        rdn = RDN(value)
    except Exception, e:
        return str(e)
    return None

def validate_hostmask(ugettext, hostmask):
    try:
        netaddr.IPNetwork(hostmask)
    except (ValueError, AddrFormatError):
        return _('invalid hostmask')


class ForwarderValidationError(Exception):
    format = None

    def __init__(self, format=None, message=None, **kw):
        messages.process_message_arguments(self, format, message, **kw)
        super(ForwarderValidationError, self).__init__(self.msg)


class UnresolvableRecordError(ForwarderValidationError):
    format = _("query '%(owner)s %(rtype)s': %(error)s")


class EDNS0UnsupportedError(ForwarderValidationError):
    format = _("query '%(owner)s %(rtype)s' with EDNS0: %(error)s")


class DNSSECSignatureMissingError(ForwarderValidationError):
    format = _("answer to query '%(owner)s %(rtype)s' is missing DNSSEC "
               "signatures (no RRSIG data)")


class DNSSECValidationError(ForwarderValidationError):
    format = _("record '%(owner)s %(rtype)s' "
               "failed DNSSEC validation on server %(ip)s")


def _log_response(log, e):
    """
    If exception contains response from server, log this response to debug log
    :param log: if log is None, do not log
    :param e: DNSException
    """
    assert isinstance(e, DNSException)
    if log is not None:
        response = getattr(e, 'kwargs', {}).get('response')
        if response:
            log.debug("DNSException: %s; server response: %s", e, response)


def _resolve_record(owner, rtype, nameserver_ip=None, edns0=False,
                    dnssec=False, flag_cd=False, timeout=10):
    """
    :param nameserver_ip: if None, default resolvers will be used
    :param edns0: enables EDNS0
    :param dnssec: enabled EDNS0, flags: DO
    :param flag_cd: requires dnssec=True, adds flag CD
    :raise DNSException: if error occurs
    """
    assert isinstance(nameserver_ip, basestring)
    assert isinstance(rtype, basestring)

    res = dns.resolver.Resolver()
    if nameserver_ip:
        res.nameservers = [nameserver_ip]
    res.lifetime = timeout

    # Recursion Desired,
    # this option prevents to get answers in authority section instead of answer
    res.set_flags(dns.flags.RD)

    if dnssec:
        res.use_edns(0, dns.flags.DO, 4096)
        flags = dns.flags.RD
        if flag_cd:
            flags = flags | dns.flags.CD
        res.set_flags(flags)
    elif edns0:
        res.use_edns(0, 0, 4096)

    return res.query(owner, rtype)


def _validate_edns0_forwarder(owner, rtype, ip_addr, log=None, timeout=10):
    """
    Validate if forwarder supports EDNS0

    :raise UnresolvableRecordError: record cannot be resolved
    :raise EDNS0UnsupportedError: EDNS0 is not supported by forwarder
    """

    try:
        _resolve_record(owner, rtype, nameserver_ip=ip_addr, timeout=timeout)
    except DNSException as e:
        _log_response(log, e)
        raise UnresolvableRecordError(owner=owner, rtype=rtype, ip=ip_addr,
                                      error=e)

    try:
        _resolve_record(owner, rtype, nameserver_ip=ip_addr, edns0=True,
                        timeout=timeout)
    except DNSException as e:
        _log_response(log, e)
        raise EDNS0UnsupportedError(owner=owner, rtype=rtype, ip=ip_addr,
                                    error=e)


def validate_dnssec_global_forwarder(ip_addr, log=None, timeout=10):
    """Test DNS forwarder properties. against root zone.

    Global forwarders should be able return signed root zone

    :raise UnresolvableRecordError: record cannot be resolved
    :raise EDNS0UnsupportedError: EDNS0 is not supported by forwarder
    :raise DNSSECSignatureMissingError: did not receive RRSIG for root zone
    """

    ip_addr = str(ip_addr)
    owner = "."
    rtype = "SOA"

    _validate_edns0_forwarder(owner, rtype, ip_addr, log=log, timeout=timeout)

    # DNS root has to be signed
    try:
        ans = _resolve_record(owner, rtype, nameserver_ip=ip_addr, dnssec=True,
                              timeout=timeout)
    except DNSException as e:
        _log_response(log, e)
        raise UnresolvableRecordError(owner=owner, rtype=rtype, ip=ip_addr,
                                      error=e)

    try:
        ans.response.find_rrset(
            ans.response.answer, dns.name.root, dns.rdataclass.IN,
            dns.rdatatype.RRSIG, dns.rdatatype.SOA
        )
    except KeyError:
        raise DNSSECSignatureMissingError(owner=owner, rtype=rtype, ip=ip_addr)


def validate_dnssec_zone_forwarder_step1(ip_addr, fwzone, log=None, timeout=10):
    """
    Only forwarders in forward zones can be validated in this way
    :raise UnresolvableRecordError: record cannot be resolved
    :raise EDNS0UnsupportedError: ENDS0 is not supported by forwarder
    """
    _validate_edns0_forwarder(fwzone, "SOA", ip_addr, log=log, timeout=timeout)


def validate_dnssec_zone_forwarder_step2(ipa_ip_addr, fwzone, log=None,
                                         timeout=10):
    """
    This step must be executed after forwarders are added into LDAP, and only
    when we are sure the forwarders work.
    Query will be send to IPA DNS server, to verify if reply passed,
    or DNSSEC validation failed.
    Only forwarders in forward zones can be validated in this way
    :raise UnresolvableRecordError: record cannot be resolved
    :raise DNSSECValidationError: response from forwarder is not DNSSEC valid
    """
    rtype = "SOA"
    try:
        ans_cd = _resolve_record(fwzone, rtype, nameserver_ip=ipa_ip_addr,
                                 edns0=True, dnssec=True, flag_cd=True,
                                 timeout=timeout)
    except DNSException as e:
        _log_response(log, e)

    try:
        ans_do = _resolve_record(fwzone, rtype, nameserver_ip=ipa_ip_addr,
                                 edns0=True, dnssec=True, timeout=timeout)
    except NXDOMAIN as e:
        # sometimes CD flag is ignored and NXDomain is returned
        _log_response(log, e)
        raise DNSSECValidationError(owner=fwzone, rtype=rtype, ip=ipa_ip_addr)
    except DNSException as e:
        _log_response(log, e)
        raise UnresolvableRecordError(owner=fwzone, rtype=rtype, ip=ipa_ip_addr,
                                      error=e)
    else:
        if (ans_do.canonical_name == ans_cd.canonical_name
            and ans_do.rrset == ans_cd.rrset):
            return
        # records received with and without CD flag are not equivalent:
        # this might be caused by an DNSSEC validation failure in cases where
        # existing zone id being 'shadowed' by another zone on forwarder
        raise DNSSECValidationError(owner=fwzone, rtype=rtype, ip=ipa_ip_addr)


def validate_idna_domain(value):
    """
    Validate if value is valid IDNA domain.

    If domain is not valid, raises ValueError
    :param value:
    :return:
    """
    error = None

    try:
        DNSName(value)
    except dns.name.BadEscape:
        error = _('invalid escape code in domain name')
    except dns.name.EmptyLabel:
        error = _('empty DNS label')
    except dns.name.NameTooLong:
        error = _('domain name cannot be longer than 255 characters')
    except dns.name.LabelTooLong:
        error = _('DNS label cannot be longer than 63 characters')
    except dns.exception.SyntaxError:
        error = _('invalid domain name')
    else:
        #compare if IDN normalized and original domain match
        #there is N:1 mapping between unicode and IDNA names
        #user should use normalized names to avoid mistakes
        labels = re.split(u'[.\uff0e\u3002\uff61]', value, flags=re.UNICODE)
        try:
            map(lambda label: label.encode("ascii"), labels)
        except UnicodeError:
            # IDNA
            is_nonnorm = any(encodings.idna.nameprep(x) != x for x in labels)
            if is_nonnorm:
                error = _("domain name '%(domain)s' should be normalized to"
                          ": %(normalized)s") % {
                          'domain': value,
                          'normalized': '.'.join([encodings.idna.nameprep(x)
                                                  for x in labels])}

    if error:
        raise ValueError(error)


def create_topology_graph(masters, segments):
    """
    Create an oriented graph from topology defined by masters and segments.

    :param masters
    :param segments
    :returns: Graph
    """
    graph = Graph()

    for m in masters:
        graph.add_vertex(m['cn'][0])

    for s in segments:
        direction = s['iparepltoposegmentdirection'][0]
        left = s['iparepltoposegmentleftnode'][0]
        right = s['iparepltoposegmentrightnode'][0]
        try:
            if direction == u'both':
                graph.add_edge(left, right)
                graph.add_edge(right, left)
            elif direction == u'left-right':
                graph.add_edge(left, right)
            elif direction == u'right-left':
                graph.add_edge(right, left)
        except ValueError:  # ignore segments with deleted master
            pass

    return graph


def get_topology_connection_errors(graph):
    """
    Traverse graph from each master and find out which masters are not
    reachable.

    :param graph: topology graph where vertices are masters
    :returns: list of errors, error is: (master, visited, not_visited)
    """
    connect_errors = []
    master_cns = list(graph.vertices)
    master_cns.sort()
    for m in master_cns:
        visited = graph.bfs(m)
        not_visited = graph.vertices - visited
        if not_visited:
            connect_errors.append((m, list(visited), list(not_visited)))
    return connect_errors
