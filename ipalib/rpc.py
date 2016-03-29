# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
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
RPC client and shared RPC client/server functionality.

This module adds some additional functionality on top of the ``xmlrpclib``
module in the Python standard library.  For documentation on the
``xmlrpclib`` module, see:

    http://docs.python.org/library/xmlrpclib.html

Also see the `ipaserver.rpcserver` module.
"""

from types import NoneType
from decimal import Decimal
import sys
import datetime
import os
import locale
import base64
import urllib
import json
import socket
from urllib2 import urlparse

from xmlrpclib import (Binary, Fault, DateTime, dumps, loads, ServerProxy,
        Transport, ProtocolError, MININT, MAXINT)
import kerberos
from dns import resolver, rdatatype
from dns.exception import DNSException
from nss.error import NSPRError

from ipalib.backend import Connectible
from ipalib.constants import LDAP_GENERALIZED_TIME_FORMAT
from ipalib.errors import (public_errors, UnknownError, NetworkError,
    KerberosError, XMLRPCMarshallError, JSONError, ConversionError)
from ipalib import errors, capabilities
from ipalib.request import context, Connection
from ipalib.util import get_current_principal
from ipapython.ipa_log_manager import root_logger
from ipapython import ipautil
from ipapython import kernel_keyring
from ipaplatform.paths import paths
from ipapython.cookie import Cookie
from ipapython.dnsutil import DNSName
from ipalib.text import _
import ipapython.nsslib
from ipapython.nsslib import NSSHTTPS, NSSConnection
from ipalib.krb_utils import KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, KRB5KRB_AP_ERR_TKT_EXPIRED, \
                             KRB5_FCC_PERM, KRB5_FCC_NOFILE, KRB5_CC_FORMAT, KRB5_REALM_CANT_RESOLVE
from ipapython.dn import DN
from ipalib.capabilities import VERSION_WITHOUT_CAPABILITIES
from ipalib import api

COOKIE_NAME = 'ipa_session'
KEYRING_COOKIE_NAME = '%s_cookie:%%s' % COOKIE_NAME

errors_by_code = dict((e.errno, e) for e in public_errors)


def client_session_keyring_keyname(principal):
    '''
    Return the key name used for storing the client session data for
    the given principal.
    '''

    return KEYRING_COOKIE_NAME % principal

def update_persistent_client_session_data(principal, data):
    '''
    Given a principal create or update the session data for that
    principal in the persistent secure storage.

    Raises ValueError if unable to perform the action for any reason.
    '''

    try:
        keyname = client_session_keyring_keyname(principal)
    except Exception, e:
        raise ValueError(str(e))

    # kernel_keyring only raises ValueError (why??)
    kernel_keyring.update_key(keyname, data)

def read_persistent_client_session_data(principal):
    '''
    Given a principal return the stored session data for that
    principal from the persistent secure storage.

    Raises ValueError if unable to perform the action for any reason.
    '''

    try:
        keyname = client_session_keyring_keyname(principal)
    except Exception, e:
        raise ValueError(str(e))

    # kernel_keyring only raises ValueError (why??)
    return kernel_keyring.read_key(keyname)

def delete_persistent_client_session_data(principal):
    '''
    Given a principal remove the session data for that
    principal from the persistent secure storage.

    Raises ValueError if unable to perform the action for any reason.
    '''

    try:
        keyname = client_session_keyring_keyname(principal)
    except Exception, e:
        raise ValueError(str(e))

    # kernel_keyring only raises ValueError (why??)
    kernel_keyring.del_key(keyname)

def xml_wrap(value, version):
    """
    Wrap all ``str`` in ``xmlrpclib.Binary``.

    Because ``xmlrpclib.dumps()`` will itself convert all ``unicode`` instances
    into UTF-8 encoded ``str`` instances, we don't do it here.

    So in total, when encoding data for an XML-RPC packet, the following
    transformations occur:

        * All ``str`` instances are treated as binary data and are wrapped in
          an ``xmlrpclib.Binary()`` instance.

        * Only ``unicode`` instances are treated as character data. They get
          converted to UTF-8 encoded ``str`` instances (although as mentioned,
          not by this function).

    Also see `xml_unwrap()`.

    :param value: The simple scalar or simple compound value to wrap.
    """
    if type(value) in (list, tuple):
        return tuple(xml_wrap(v, version) for v in value)
    if isinstance(value, dict):
        return dict(
            (k, xml_wrap(v, version)) for (k, v) in value.iteritems()
        )
    if type(value) is str:
        return Binary(value)
    if type(value) is Decimal:
        # transfer Decimal as a string
        return unicode(value)
    if isinstance(value, (int, long)) and (value < MININT or value > MAXINT):
        return unicode(value)
    if isinstance(value, DN):
        return str(value)

    # Encode datetime.datetime objects as xmlrpclib.DateTime objects
    if isinstance(value, datetime.datetime):
        if capabilities.client_has_capability(version, 'datetime_values'):
            return DateTime(value)
        else:
            return value.strftime(LDAP_GENERALIZED_TIME_FORMAT)

    if isinstance(value, DNSName):
        if capabilities.client_has_capability(version, 'dns_name_values'):
            return {'__dns_name__': unicode(value)}
        else:
            return unicode(value)

    assert type(value) in (unicode, int, long, float, bool, NoneType)
    return value


def xml_unwrap(value, encoding='UTF-8'):
    """
    Unwrap all ``xmlrpc.Binary``, decode all ``str`` into ``unicode``.

    When decoding data from an XML-RPC packet, the following transformations
    occur:

        * The binary payloads of all ``xmlrpclib.Binary`` instances are
          returned as ``str`` instances.

        * All ``str`` instances are treated as UTF-8 encoded Unicode strings.
          They are decoded and the resulting ``unicode`` instance is returned.

    Also see `xml_wrap()`.

    :param value: The value to unwrap.
    :param encoding: The Unicode encoding to use (defaults to ``'UTF-8'``).
    """
    if type(value) in (list, tuple):
        return tuple(xml_unwrap(v, encoding) for v in value)
    if type(value) is dict:
        if '__dns_name__' in value:
            return DNSName(value['__dns_name__'])
        else:
            return dict(
                (k, xml_unwrap(v, encoding)) for (k, v) in value.iteritems()
            )
    if type(value) is str:
        return value.decode(encoding)
    if isinstance(value, Binary):
        assert type(value.data) is str
        return value.data
    if isinstance(value, DateTime):
        # xmlprc DateTime is converted to string of %Y%m%dT%H:%M:%S format
        return datetime.datetime.strptime(str(value), "%Y%m%dT%H:%M:%S")
    assert type(value) in (unicode, int, float, bool, NoneType)
    return value


def xml_dumps(params, version, methodname=None, methodresponse=False,
              encoding='UTF-8'):
    """
    Encode an XML-RPC data packet, transparently wraping ``params``.

    This function will wrap ``params`` using `xml_wrap()` and will
    then encode the XML-RPC data packet using ``xmlrpclib.dumps()`` (from the
    Python standard library).

    For documentation on the ``xmlrpclib.dumps()`` function, see:

        http://docs.python.org/library/xmlrpclib.html#convenience-functions

    Also see `xml_loads()`.

    :param params: A ``tuple`` or an ``xmlrpclib.Fault`` instance.
    :param methodname: The name of the method to call if this is a request.
    :param methodresponse: Set this to ``True`` if this is a response.
    :param encoding: The Unicode encoding to use (defaults to ``'UTF-8'``).
    """
    if type(params) is tuple:
        params = xml_wrap(params, version)
    else:
        assert isinstance(params, Fault)
    return dumps(params,
        methodname=methodname,
        methodresponse=methodresponse,
        encoding=encoding,
        allow_none=True,
    )


def json_encode_binary(val, version):
    '''
   JSON cannot encode binary values. We encode binary values in Python str
   objects and text in Python unicode objects. In order to allow a binary
   object to be passed through JSON we base64 encode it thus converting it to
   text which JSON can transport. To assure we recognize the value is a base64
   encoded representation of the original binary value and not confuse it with
   other text we convert the binary value to a dict in this form:

   {'__base64__' : base64_encoding_of_binary_value}

   This modification of the original input value cannot be done "in place" as
   one might first assume (e.g. replacing any binary items in a container
   (e.g. list, tuple, dict) with the base64 dict because the container might be
   an immutable object (i.e. a tuple). Therefore this function returns a copy
   of any container objects it encounters with tuples replaced by lists. This
   is O.K. because the JSON encoding will map both lists and tuples to JSON
   arrays.
   '''

    if isinstance(val, dict):
        new_dict = {}
        for k, v in val.items():
            new_dict[k] = json_encode_binary(v, version)
        return new_dict
    elif isinstance(val, (list, tuple)):
        new_list = [json_encode_binary(v, version) for v in val]
        return new_list
    elif isinstance(val, str):
        return {'__base64__': base64.b64encode(val)}
    elif isinstance(val, Decimal):
        return {'__base64__': base64.b64encode(str(val))}
    elif isinstance(val, DN):
        return str(val)
    elif isinstance(val, datetime.datetime):
        if capabilities.client_has_capability(version, 'datetime_values'):
            return {'__datetime__': val.strftime(LDAP_GENERALIZED_TIME_FORMAT)}
        else:
            return val.strftime(LDAP_GENERALIZED_TIME_FORMAT)
    elif isinstance(val, DNSName):
        if capabilities.client_has_capability(version, 'dns_name_values'):
            return {'__dns_name__': unicode(val)}
        else:
            return unicode(val)
    else:
        return val


def json_decode_binary(val):
    '''
    JSON cannot transport binary data. In order to transport binary data we
    convert binary data to a form like this:

   {'__base64__' : base64_encoding_of_binary_value}

   see json_encode_binary()

    After JSON had decoded the JSON stream back into a Python object we must
    recursively scan the object looking for any dicts which might represent
    binary values and replace the dict containing the base64 encoding of the
    binary value with the decoded binary value. Unlike the encoding problem
    where the input might consist of immutable object, all JSON decoded
    container are mutable so the conversion could be done in place. However we
    don't modify objects in place because of side effects which may be
    dangerous. Thus we elect to spend a few more cycles and avoid the
    possibility of unintended side effects in favor of robustness.
    '''

    if isinstance(val, dict):
        if '__base64__' in val:
            return base64.b64decode(val['__base64__'])
        elif '__datetime__' in val:
            return datetime.datetime.strptime(val['__datetime__'],
                                              LDAP_GENERALIZED_TIME_FORMAT)
        elif '__dns_name__' in val:
            return DNSName(val['__dns_name__'])
        else:
            return dict((k, json_decode_binary(v)) for k, v in val.items())
    elif isinstance(val, list):
        return tuple(json_decode_binary(v) for v in val)
    else:
        if isinstance(val, basestring):
            try:
                return val.decode('utf-8')
            except UnicodeDecodeError:
                raise ConversionError(
                    name=val,
                    error='incorrect type'
                )
        else:
            return val


def decode_fault(e, encoding='UTF-8'):
    assert isinstance(e, Fault)
    if type(e.faultString) is str:
        return Fault(e.faultCode, e.faultString.decode(encoding))
    return e


def xml_loads(data, encoding='UTF-8'):
    """
    Decode the XML-RPC packet in ``data``, transparently unwrapping its params.

    This function will decode the XML-RPC packet in ``data`` using
    ``xmlrpclib.loads()`` (from the Python standard library).  If ``data``
    contains a fault, ``xmlrpclib.loads()`` will itself raise an
    ``xmlrpclib.Fault`` exception.

    Assuming an exception is not raised, this function will then unwrap the
    params in ``data`` using `xml_unwrap()`.  Finally, a
    ``(params, methodname)`` tuple is returned containing the unwrapped params
    and the name of the method being called.  If the packet contains no method
    name, ``methodname`` will be ``None``.

    For documentation on the ``xmlrpclib.loads()`` function, see:

        http://docs.python.org/library/xmlrpclib.html#convenience-functions

    Also see `xml_dumps()`.

    :param data: The XML-RPC packet to decode.
    """
    try:
        (params, method) = loads(data)
        return (xml_unwrap(params), method)
    except Fault, e:
        raise decode_fault(e)


class DummyParser(object):
    def __init__(self):
        self.data = ''

    def feed(self, data):
        self.data += data

    def close(self):
        return self.data


class MultiProtocolTransport(Transport):
    """Transport that handles both XML-RPC and JSON"""
    def __init__(self, protocol):
        Transport.__init__(self)
        self.protocol = protocol

    def getparser(self):
        if self.protocol == 'json':
            parser = DummyParser()
            return parser, parser
        else:
            return Transport.getparser(self)

    def send_content(self, connection, request_body):
        if self.protocol == 'json':
            connection.putheader("Content-Type", "application/json")
        else:
            connection.putheader("Content-Type", "text/xml")

        # gzip compression would be set up here, but we have it turned off
        # (encode_threshold is None)

        connection.putheader("Content-Length", str(len(request_body)))
        connection.endheaders(request_body)


class LanguageAwareTransport(MultiProtocolTransport):
    """Transport sending Accept-Language header"""
    def get_host_info(self, host):
        host, extra_headers, x509 = MultiProtocolTransport.get_host_info(
            self, host)

        try:
            lang = locale.setlocale(locale.LC_ALL, '').split('.')[0].lower()
        except locale.Error:
            # fallback to default locale
            lang = 'en_us'

        if not isinstance(extra_headers, list):
            extra_headers = []

        extra_headers.append(
            ('Accept-Language', lang.replace('_', '-'))
        )
        extra_headers.append(
            ('Referer', 'https://%s/ipa/xml' % str(host))
        )

        return (host, extra_headers, x509)

class SSLTransport(LanguageAwareTransport):
    """Handles an HTTPS transaction to an XML-RPC server."""

    def get_connection_dbdir(self):
        """
        If there is a connections open it may have already initialized
        NSS database. Return the database location used by the connection.
        """
        for value in context.__dict__.values():
            if not isinstance(value, Connection):
                continue
            if not isinstance(
                    getattr(value.conn, '_ServerProxy__transport', None),
                    SSLTransport):
                continue
            if hasattr(value.conn._ServerProxy__transport, 'dbdir'):
                return value.conn._ServerProxy__transport.dbdir
        return None

    def make_connection(self, host):
        host, self._extra_headers, x509 = self.get_host_info(host)
        # Python 2.7 changed the internal class used in xmlrpclib from
        # HTTP to HTTPConnection. We need to use the proper subclass

        if sys.version_info >= (2, 7):
            if self._connection and host == self._connection[0]:
                return self._connection[1]

        dbdir = getattr(context, 'nss_dir', paths.IPA_NSSDB_DIR)
        connection_dbdir = self.get_connection_dbdir()

        if connection_dbdir:
            # If an existing connection is already using the same NSS
            # database there is no need to re-initialize.
            no_init = dbdir == connection_dbdir

        else:
            # If the NSS database is already being used there is no
            # need to re-initialize.
            no_init = dbdir == ipapython.nsslib.current_dbdir

        if sys.version_info < (2, 7):
            conn = NSSHTTPS(host, 443, dbdir=dbdir, no_init=no_init)
        else:
            conn = NSSConnection(host, 443, dbdir=dbdir, no_init=no_init,
                                 tls_version_min=api.env.tls_version_min,
                                 tls_version_max=api.env.tls_version_max)
        self.dbdir=dbdir

        conn.connect()
        if sys.version_info < (2, 7):
            return conn
        else:
            self._connection = host, conn
            return self._connection[1]


class KerbTransport(SSLTransport):
    """
    Handles Kerberos Negotiation authentication to an XML-RPC server.
    """
    flags = kerberos.GSS_C_MUTUAL_FLAG | kerberos.GSS_C_SEQUENCE_FLAG

    def _handle_exception(self, e, service=None):
        (major, minor) = ipautil.get_gsserror(e)
        if minor[1] == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
            raise errors.ServiceError(service=service)
        elif minor[1] == KRB5_FCC_NOFILE:
            raise errors.NoCCacheError()
        elif minor[1] == KRB5KRB_AP_ERR_TKT_EXPIRED:
            raise errors.TicketExpired()
        elif minor[1] == KRB5_FCC_PERM:
            raise errors.BadCCachePerms()
        elif minor[1] == KRB5_CC_FORMAT:
            raise errors.BadCCacheFormat()
        elif minor[1] == KRB5_REALM_CANT_RESOLVE:
            raise errors.CannotResolveKDC()
        else:
            raise errors.KerberosError(major=major, minor=minor)

    def get_host_info(self, host):
        """
        Two things can happen here. If we have a session we will add
        a cookie for that. If not we will set an Authorization header.
        """
        (host, extra_headers, x509) = SSLTransport.get_host_info(self, host)

        if not isinstance(extra_headers, list):
            extra_headers = []

        session_cookie = getattr(context, 'session_cookie', None)
        if session_cookie:
            extra_headers.append(('Cookie', session_cookie))
            return (host, extra_headers, x509)

        # Set the remote host principal
        service = "HTTP@" + host.split(':')[0]

        try:
            (rc, vc) = kerberos.authGSSClientInit(service=service,
                                                  gssflags=self.flags)
        except kerberos.GSSError, e:
            self._handle_exception(e)

        try:
            kerberos.authGSSClientStep(vc, "")
        except kerberos.GSSError, e:
            self._handle_exception(e, service=service)

        for (h, v) in extra_headers:
            if h == 'Authorization':
                extra_headers.remove((h, v))
                break

        extra_headers.append(
            ('Authorization', 'negotiate %s' % kerberos.authGSSClientResponse(vc))
        )

        return (host, extra_headers, x509)

    def single_request(self, host, handler, request_body, verbose=0):
        try:
            return SSLTransport.single_request(self, host, handler, request_body, verbose)
        finally:
            self.close()

    def store_session_cookie(self, cookie_header):
        '''
        Given the contents of a Set-Cookie header scan the header and
        extract each cookie contained within until the session cookie
        is located. Examine the session cookie if the domain and path
        are specified, if not update the cookie with those values from
        the request URL. Then write the session cookie into the key
        store for the principal. If the cookie header is None or the
        session cookie is not present in the header no action is
        taken.

        Context Dependencies:

        The per thread context is expected to contain:
            principal
                The current pricipal the HTTP request was issued for.
            request_url
                The URL of the HTTP request.

        '''

        if cookie_header is None:
            return

        principal = getattr(context, 'principal', None)
        request_url = getattr(context, 'request_url', None)
        root_logger.debug("received Set-Cookie '%s'", cookie_header)

        # Search for the session cookie
        try:
            session_cookie = Cookie.get_named_cookie_from_string(cookie_header,
                                                                 COOKIE_NAME, request_url)
        except Exception, e:
            root_logger.error("unable to parse cookie header '%s': %s", cookie_header, e)
            return

        if session_cookie is None:
            return

        cookie_string = str(session_cookie)
        root_logger.debug("storing cookie '%s' for principal %s", cookie_string, principal)
        try:
            update_persistent_client_session_data(principal, cookie_string)
        except Exception, e:
            # Not fatal, we just can't use the session cookie we were sent.
            pass

    def parse_response(self, response):
        self.store_session_cookie(response.getheader('Set-Cookie'))
        return SSLTransport.parse_response(self, response)


class DelegatedKerbTransport(KerbTransport):
    """
    Handles Kerberos Negotiation authentication and TGT delegation to an
    XML-RPC server.
    """
    flags = kerberos.GSS_C_DELEG_FLAG |  kerberos.GSS_C_MUTUAL_FLAG | \
            kerberos.GSS_C_SEQUENCE_FLAG


class RPCClient(Connectible):
    """
    Forwarding backend plugin for XML-RPC client.

    Also see the `ipaserver.rpcserver.xmlserver` plugin.
    """

    # Values to set on subclasses:
    session_path = None
    server_proxy_class = ServerProxy
    protocol = None
    env_rpc_uri_key = None

    def get_url_list(self, rpc_uri):
        """
        Create a list of urls consisting of the available IPA servers.
        """
        # the configured URL defines what we use for the discovered servers
        (scheme, netloc, path, params, query, fragment
            ) = urlparse.urlparse(rpc_uri)
        servers = []
        name = '_ldap._tcp.%s.' % self.env.domain

        try:
            answers = resolver.query(name, rdatatype.SRV)
        except DNSException, e:
            answers = []

        for answer in answers:
            server = str(answer.target).rstrip(".")
            servers.append('https://%s%s' % (ipautil.format_netloc(server), path))

        servers = list(set(servers))
        # the list/set conversion won't preserve order so stick in the
        # local config file version here.
        cfg_server = rpc_uri
        if cfg_server in servers:
            # make sure the configured master server is there just once and
            # it is the first one
            servers.remove(cfg_server)
            servers.insert(0, cfg_server)
        else:
            servers.insert(0, cfg_server)

        return servers

    def get_session_cookie_from_persistent_storage(self, principal):
        '''
        Retrieves the session cookie for the given principal from the
        persistent secure storage. Returns None if not found or unable
        to retrieve the session cookie for any reason, otherwise
        returns a Cookie object containing the session cookie.
        '''

        # Get the session data, it should contain a cookie string
        # (possibly with more than one cookie).
        try:
            cookie_string = read_persistent_client_session_data(principal)
        except Exception, e:
            return None

        # Search for the session cookie within the cookie string
        try:
            session_cookie = Cookie.get_named_cookie_from_string(cookie_string, COOKIE_NAME)
        except Exception, e:
            return None

        return session_cookie

    def apply_session_cookie(self, url):
        '''
        Attempt to load a session cookie for the current principal
        from the persistent secure storage. If the cookie is
        successfully loaded adjust the input url's to point to the
        session path and insert the session cookie into the per thread
        context for later insertion into the HTTP request. If the
        cookie is not successfully loaded then the original url is
        returned and the per thread context is not modified.

        Context Dependencies:

        The per thread context is expected to contain:
            principal
                The current pricipal the HTTP request was issued for.

        The per thread context will be updated with:
            session_cookie
                A cookie string to be inserted into the Cookie header
                of the HTPP request.

        '''

        original_url = url
        principal = getattr(context, 'principal', None)

        session_cookie = self.get_session_cookie_from_persistent_storage(principal)
        if session_cookie is None:
            self.log.debug("failed to find session_cookie in persistent storage for principal '%s'",
                           principal)
            return original_url
        else:
            self.debug("found session_cookie in persistent storage for principal '%s', cookie: '%s'",
                       principal, session_cookie)

        # Decide if we should send the cookie to the server
        try:
            session_cookie.http_return_ok(original_url)
        except Cookie.Expired, e:
            self.debug("deleting session data for principal '%s': %s", principal, e)
            try:
                delete_persistent_client_session_data(principal)
            except Exception, e:
                pass
            return original_url
        except Cookie.URLMismatch, e:
            self.debug("not sending session cookie, URL mismatch: %s", e)
            return original_url
        except Exception, e:
            self.error("not sending session cookie, unknown error: %s", e)
            return original_url

        # O.K. session_cookie is valid to be returned, stash it away where it will will
        # get included in a HTTP Cookie headed sent to the server.
        self.log.debug("setting session_cookie into context '%s'", session_cookie.http_cookie())
        setattr(context, 'session_cookie', session_cookie.http_cookie())

        # Form the session URL by substituting the session path into the original URL
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(original_url)
        path = self.session_path
        session_url = urlparse.urlunparse((scheme, netloc, path, params, query, fragment))

        return session_url

    def create_connection(self, ccache=None, verbose=0, fallback=True,
                          delegate=False, nss_dir=None):
        try:
            rpc_uri = self.env[self.env_rpc_uri_key]
            principal = get_current_principal()
            setattr(context, 'principal', principal)
            # We have a session cookie, try using the session URI to see if it
            # is still valid
            if not delegate:
                rpc_uri = self.apply_session_cookie(rpc_uri)
        except ValueError:
            # No session key, do full Kerberos auth
            pass
        # This might be dangerous. Use at your own risk!
        if nss_dir:
            context.nss_dir = nss_dir
        urls = self.get_url_list(rpc_uri)
        serverproxy = None
        for url in urls:
            kw = dict(allow_none=True, encoding='UTF-8')
            kw['verbose'] = verbose
            if url.startswith('https://'):
                if delegate:
                    transport_class = DelegatedKerbTransport
                else:
                    transport_class = KerbTransport
            else:
                transport_class = LanguageAwareTransport
            kw['transport'] = transport_class(protocol=self.protocol)
            self.log.info('trying %s' % url)
            setattr(context, 'request_url', url)
            serverproxy = self.server_proxy_class(url, **kw)
            if len(urls) == 1:
                # if we have only 1 server and then let the
                # main requester handle any errors. This also means it
                # must handle a 401 but we save a ping.
                return serverproxy
            try:
                command = getattr(serverproxy, 'ping')
                try:
                    response = command([], {})
                except Fault, e:
                    e = decode_fault(e)
                    if e.faultCode in errors_by_code:
                        error = errors_by_code[e.faultCode]
                        raise error(message=e.faultString)
                    else:
                        raise UnknownError(
                            code=e.faultCode,
                            error=e.faultString,
                            server=url,
                        )
                # We don't care about the response, just that we got one
                break
            except KerberosError, krberr:
                # kerberos error on one server is likely on all
                raise errors.KerberosError(major=str(krberr), minor='')
            except ProtocolError, e:
                if hasattr(context, 'session_cookie') and e.errcode == 401:
                    # Unauthorized. Remove the session and try again.
                    delattr(context, 'session_cookie')
                    try:
                        delete_persistent_client_session_data(principal)
                    except Exception, e:
                        # This shouldn't happen if we have a session but it isn't fatal.
                        pass
                    return self.create_connection(ccache, verbose, fallback, delegate)
                if not fallback:
                    raise
                serverproxy = None
            except Exception, e:
                if not fallback:
                    raise
                else:
                    self.log.info('Connection to %s failed with %s', url, e)
                serverproxy = None

        if serverproxy is None:
            raise NetworkError(uri=_('any of the configured servers'),
                error=', '.join(urls))
        return serverproxy

    def destroy_connection(self):
        if sys.version_info >= (2, 7):
            conn = getattr(context, self.id, None)
            if conn is not None:
                conn = conn.conn._ServerProxy__transport
                conn.close()

    def _call_command(self, command, params):
        """Call the command with given params"""
        # For XML, this method will wrap/unwrap binary values
        # For JSON we do that in the proxy
        return command(*params)

    def forward(self, name, *args, **kw):
        """
        Forward call to command named ``name`` over XML-RPC.

        This method will encode and forward an XML-RPC request, and will then
        decode and return the corresponding XML-RPC response.

        :param command: The name of the command being forwarded.
        :param args: Positional arguments to pass to remote command.
        :param kw: Keyword arguments to pass to remote command.
        """
        if name not in self.Command:
            raise ValueError(
                '%s.forward(): %r not in api.Command' % (self.name, name)
            )
        server = getattr(context, 'request_url', None)
        self.log.info("Forwarding '%s' to %s server '%s'",
                      name, self.protocol, server)
        command = getattr(self.conn, name)
        params = [args, kw]
        try:
            return self._call_command(command, params)
        except Fault, e:
            e = decode_fault(e)
            self.debug('Caught fault %d from server %s: %s', e.faultCode,
                server, e.faultString)
            if e.faultCode in errors_by_code:
                error = errors_by_code[e.faultCode]
                raise error(message=e.faultString)
            raise UnknownError(
                code=e.faultCode,
                error=e.faultString,
                server=server,
            )
        except NSPRError, e:
            raise NetworkError(uri=server, error=str(e))
        except ProtocolError, e:
            # By catching a 401 here we can detect the case where we have
            # a single IPA server and the session is invalid. Otherwise
            # we always have to do a ping().
            session_cookie = getattr(context, 'session_cookie', None)
            if session_cookie and e.errcode == 401:
                # Unauthorized. Remove the session and try again.
                delattr(context, 'session_cookie')
                try:
                    principal = getattr(context, 'principal', None)
                    delete_persistent_client_session_data(principal)
                except Exception, e:
                    # This shouldn't happen if we have a session but it isn't fatal.
                    pass

                # Create a new serverproxy with the non-session URI. If there
                # is an existing connection we need to save the NSS dbdir so
                # we can skip an unnecessary NSS_Initialize() and avoid
                # NSS_Shutdown issues.
                serverproxy = self.create_connection(os.environ.get('KRB5CCNAME'), self.env.verbose, self.env.fallback, self.env.delegate)

                dbdir = None
                current_conn = getattr(context, self.id, None)
                if current_conn is not None:
                    dbdir = getattr(current_conn.conn._ServerProxy__transport, 'dbdir', None)
                    if dbdir is not None:
                        self.debug('Using dbdir %s' % dbdir)
                setattr(context, self.id, Connection(serverproxy, self.disconnect))
                if dbdir is not None:
                    current_conn = getattr(context, self.id, None)
                    current_conn.conn._ServerProxy__transport.dbdir = dbdir
                return self.forward(name, *args, **kw)
            raise NetworkError(uri=server, error=e.errmsg)
        except socket.error, e:
            raise NetworkError(uri=server, error=str(e))
        except (OverflowError, TypeError), e:
            raise XMLRPCMarshallError(error=str(e))


class xmlclient(RPCClient):
    session_path = '/ipa/session/xml'
    server_proxy_class = ServerProxy
    protocol = 'xml'
    env_rpc_uri_key = 'xmlrpc_uri'

    def _call_command(self, command, params):
        version = params[1].get('version', VERSION_WITHOUT_CAPABILITIES)
        params = xml_wrap(params, version)
        result = command(*params)
        return xml_unwrap(result)


class JSONServerProxy(object):
    def __init__(self, uri, transport, encoding, verbose, allow_none):
        type, uri = urllib.splittype(uri)
        if type not in ("http", "https"):
            raise IOError("unsupported XML-RPC protocol")
        self.__host, self.__handler = urllib.splithost(uri)
        self.__transport = transport

        assert encoding == 'UTF-8'
        assert allow_none
        self.__verbose = verbose

        # FIXME: Some of our code requires ServerProxy internals.
        # But, xmlrpclib.ServerProxy's _ServerProxy__transport can be accessed
        # by calling serverproxy('transport')
        self._ServerProxy__transport = transport

    def __request(self, name, args):
        payload = {'method': unicode(name), 'params': args, 'id': 0}
        version = args[1].get('version', VERSION_WITHOUT_CAPABILITIES)
        payload = json_encode_binary(payload, version)

        if self.__verbose >= 2:
            root_logger.info('Request: %s',
                             json.dumps(payload, sort_keys=True, indent=4))

        response = self.__transport.request(
            self.__host,
            self.__handler,
            json.dumps(payload),
            verbose=self.__verbose >= 3,
        )

        try:
            response = json_decode_binary(json.loads(response))
        except ValueError, e:
            raise JSONError(str(e))

        if self.__verbose >= 2:
            root_logger.info(
                'Response: %s',
                json.dumps(json_encode_binary(response, version),
                           sort_keys=True, indent=4)
            )
        error = response.get('error')
        if error:
            try:
                error_class = errors_by_code[error['code']]
            except KeyError:
                raise UnknownError(
                    code=error.get('code'),
                    error=error.get('message'),
                    server=self.__host,
                )
            else:
                raise error_class(message=error['message'])

        return response['result']

    def __getattr__(self, name):
        def _call(*args):
            return self.__request(name, args)
        return _call


class jsonclient(RPCClient):
    session_path = '/ipa/session/json'
    server_proxy_class = JSONServerProxy
    protocol = 'json'
    env_rpc_uri_key = 'jsonrpc_uri'
