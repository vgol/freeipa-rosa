#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from datetime import datetime
import dns.name
import errno
import os
import logging
import shutil
import stat
import subprocess

from ipalib import api
import ipalib.constants
from ipapython.dn import DN
from ipapython import ipa_log_manager, ipautil
from ipaplatform.paths import paths

from temp import TemporaryDirectory

time_bindfmt = '%Y%m%d%H%M%S'

# this daemon should run under ods:named user:group
# user has to be ods because ODSMgr.py sends signal to ods-enforcerd
FILE_PERM = (stat.S_IRUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IWUSR)
DIR_PERM = (stat.S_IRWXU | stat.S_IRWXG)

class BINDMgr(object):
    """BIND key manager. It does LDAP->BIND key files synchronization.

    One LDAP object with idnsSecKey object class will produce
    single pair of BIND key files.
    """
    def __init__(self, api):
        self.api = api
        self.log = ipa_log_manager.log_mgr.get_logger(self)
        self.ldap_keys = {}
        self.modified_zones = set()

    def notify_zone(self, zone):
        cmd = ['rndc', 'sign', zone.to_text()]
        output = ipautil.run(cmd)[0]
        self.log.info(output)

    def dn2zone_name(self, dn):
        """cn=KSK-20140813162153Z-cede9e182fc4af76c4bddbc19123a565,cn=keys,idnsname=test,cn=dns,dc=ipa,dc=example"""
        # verify that metadata object is under DNS sub-tree
        dn = DN(dn)
        container = DN(self.api.env.container_dns, self.api.env.basedn)
        idx = dn.rfind(container)
        assert idx != -1, 'Metadata object %s is not inside %s' % (dn, container)
        assert len(dn[idx - 1]) == 1, 'Multi-valued RDN as zone name is not supported'
        return dns.name.from_text(dn[idx - 1]['idnsname'])

    def time_ldap2bindfmt(self, str_val):
        dt = datetime.strptime(str_val, ipalib.constants.LDAP_GENERALIZED_TIME_FORMAT)
        return dt.strftime(time_bindfmt)

    def dates2params(self, ldap_attrs):
        attr2param = {'idnsseckeypublish': '-P',
                'idnsseckeyactivate': '-A',
                'idnsseckeyinactive': '-I',
                'idnsseckeydelete': '-D'}

        params = []
        for attr, param in attr2param.items():
            if attr in ldap_attrs:
                params.append(param)
                assert len(ldap_attrs[attr]) == 1, 'Timestamp %s is expected to be single-valued' % attr
                params.append(self.time_ldap2bindfmt(ldap_attrs[attr][0]))

        return params

    def ldap_event(self, op, uuid, attrs):
        """Record single LDAP event - key addition, deletion or modification.

        Change is only recorded to memory.
        self.sync() has to be called to synchronize change to BIND."""
        assert op == 'add' or op == 'del' or op == 'mod'
        zone = self.dn2zone_name(attrs['dn'])
        self.modified_zones.add(zone)
        zone_keys = self.ldap_keys.setdefault(zone, {})
        if op == 'add':
            self.log.info('Key metadata %s added to zone %s' % (attrs['dn'], zone))
            zone_keys[uuid] = attrs

        elif op == 'del':
            self.log.info('Key metadata %s deleted from zone %s' % (attrs['dn'], zone))
            zone_keys.pop(uuid)

        elif op == 'mod':
            self.log.info('Key metadata %s updated in zone %s' % (attrs['dn'], zone))
            zone_keys[uuid] = attrs

    def install_key(self, zone, uuid, attrs, workdir):
        """Run dnssec-keyfromlabel on given LDAP object.
        :returns: base file name of output files, e.g. Kaaa.test.+008+19719"""
        self.log.info('attrs: %s', attrs)
        assert attrs.get('idnsseckeyzone', ['FALSE'])[0] == 'TRUE', \
            'object %s is not a DNS zone key' % attrs['dn']

        uri = "%s;pin-source=%s" % (attrs['idnsSecKeyRef'][0], paths.DNSSEC_SOFTHSM_PIN)
        cmd = [paths.DNSSEC_KEYFROMLABEL, '-K', workdir, '-a', attrs['idnsSecAlgorithm'][0], '-l', uri]
        cmd += self.dates2params(attrs)
        if attrs.get('idnsSecKeySep', ['FALSE'])[0].upper() == 'TRUE':
            cmd += ['-f', 'KSK']
        if attrs.get('idnsSecKeyRevoke', ['FALSE'])[0].upper() == 'TRUE':
            cmd += ['-R', datetime.now().strftime(time_bindfmt)]
        cmd.append(zone.to_text())

        # keys has to be readable by ODS & named
        basename = ipautil.run(cmd)[0].strip()
        private_fn = "%s/%s.private" % (workdir, basename)
        os.chmod(private_fn, FILE_PERM)
        # this is useful mainly for debugging
        with open("%s/%s.uuid" % (workdir, basename), 'w') as uuid_file:
            uuid_file.write(uuid)
        with open("%s/%s.dn" % (workdir, basename), 'w') as dn_file:
            dn_file.write(attrs['dn'])

    def get_zone_dir_name(self, zone):
        """Escape zone name to form suitable for file-system.

        This method has to be equivalent to zr_get_zone_path()
        in bind-dyndb-ldap/zone_register.c."""

        if zone == dns.name.root:
            return "@"

        # strip final (empty) label
        zone = zone.relativize(dns.name.root)
        escaped = ""
        for label in zone:
            for char in label:
                c = ord(char)
                if ((c >= 0x30 and c <= 0x39) or   # digit
                   (c >= 0x41 and c <= 0x5A) or    # uppercase
                   (c >= 0x61 and c <= 0x7A) or    # lowercase
                   c == 0x2D or                    # hyphen
                   c == 0x5F):                     # underscore
                    if (c >= 0x41 and c <= 0x5A):  # downcase
                        c += 0x20
                    escaped += chr(c)
                else:
                    escaped += "%%%02X" % c
            escaped += '.'

        # strip trailing period
        return escaped[:-1]

    def sync_zone(self, zone):
        self.log.info('Synchronizing zone %s' % zone)
        zone_path = os.path.join(paths.BIND_LDAP_DNS_ZONE_WORKDIR,
                self.get_zone_dir_name(zone))
        try:
            os.makedirs(zone_path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise e

        # fix HSM permissions
        # TODO: move out
        for prefix, dirs, files in os.walk(paths.DNSSEC_TOKENS_DIR, topdown=True):
            for name in dirs:
                fpath = os.path.join(prefix, name)
                self.log.debug('Fixing directory permissions: %s', fpath)
                os.chmod(fpath, DIR_PERM | stat.S_ISGID)
            for name in files:
                fpath = os.path.join(prefix, name)
                self.log.debug('Fixing file permissions: %s', fpath)
                os.chmod(fpath, FILE_PERM)
        # TODO: move out

        with TemporaryDirectory(zone_path) as tempdir:
            for uuid, attrs in self.ldap_keys[zone].items():
                self.install_key(zone, uuid, attrs, tempdir)
            # keys were generated in a temporary directory, swap directories
            target_dir = "%s/keys" % zone_path
            try:
                shutil.rmtree(target_dir)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise e
            shutil.move(tempdir, target_dir)
            os.chmod(target_dir, DIR_PERM)

        self.notify_zone(zone)

    def sync(self):
        """Synchronize list of zones in LDAP with BIND."""
        self.log.debug('Key metadata in LDAP: %s' % self.ldap_keys)
        for zone in self.modified_zones:
            self.sync_zone(zone)

        self.modified_zones = set()

    def diff_zl(self, s1, s2):
        """Compute zones present in s1 but not present in s2.

        Returns: List of (uuid, name) tuples with zones present only in s1."""
        s1_extra = s1.uuids - s2.uuids
        removed = [(uuid, name) for (uuid, name) in s1.mapping.items()
                   if uuid in s1_extra]
        return removed
