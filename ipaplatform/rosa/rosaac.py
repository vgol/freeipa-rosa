# Copyright (C) 2015 ROSA
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

# This module based on authconfig (see Copyright below).

# Authconfig - client authentication configuration program
# Copyright (c) 1999-2014 Red Hat, Inc.
#
# Authors: Preston Brown <pbrown@redhat.com>
#          Nalin Dahyabhai <nalin@redhat.com>
#          Matt Wilson <msw@redhat.com>
#          Tomas Mraz <tmraz@redhat.com>
#          Ray Strode <rstrode@redhat.com>
#          Paolo Bonzini <pbonzini@redhat.com>
#          Miloslav Trmac <mitr@redhat.com>
#          Jan Lieskovsky <jlieskov@redhat.com>


"""This module provides authconfig functionality for ROSA linux
platform.

"""
import gettext
import os
import re
import string
import sys
import copy
import stat
import fcntl
import tempfile
import socket
from subprocess import call, Popen, PIPE

import errno

import shutil

if sys.version_info[0] < 3:
    import urllib2 as request
    import urlparse as parse
else:
    from urllib import request
    from urllib import parse

from ipaplatform.rosa import shvfile
from ipaplatform.rosa.paths import paths

try:
    import SSSDConfig
except ImportError:
    SSSDConfig = None


_ = gettext.gettext

SYSCONFDIR = "/etc"
LIBDIR = os.sep + sys.lib

AUTH_MODULE_DIR = LIBDIR + "/security"

PATH_CONFIG_BACKUPS = "/var/lib/rosaac"

AUTH_PAM_SERVICE = "system-auth"
AUTH_PAM_SERVICE_AC = "system-auth-ac"

POSTLOGIN_PAM_SERVICE = "postlogin"
POSTLOGIN_PAM_SERVICE_AC = "postlogin-ac"

SSSD_AUTHCONFIG_DOMAIN = "default"
PATH_SSSD = "/usr/sbin/sssd"
PATH_SSSD_CONFIG = SYSCONFDIR + "/sssd/sssd.conf"

PATH_LDAP_CACERTS = "/etc/openldap/certs"

PATH_PAM_KRB5 = AUTH_MODULE_DIR + "/pam_krb5.so"
PATH_PAM_LDAP = AUTH_MODULE_DIR + "/pam_ldap.so"
PATH_LIBNSS_LDAP = "/usr" + LIBDIR + "/libnss_ldap.so.2"
if not os.path.isfile(PATH_LIBNSS_LDAP):
    PATH_LIBNSS_LDAP = LIBDIR + "/libnss_ldap.so.2"

PATH_PAM_SSS = AUTH_MODULE_DIR + "/pam_sss.so"
PATH_LIBNSS_SSS = LIBDIR + "/libnss_sss.so.2"

PATH_NSCD = "/usr/sbin/nscd"
PATH_NSLCD = "/usr/sbin/nslcd"

PATH_PAM_FPRINTD = AUTH_MODULE_DIR + "/pam_fprintd.so"

PATH_LIBSSS_AUTOFS = LIBDIR + "/sssd/modules/libsss_autofs.so"

PASSWORD_AUTH_PAM_SERVICE = "password-auth"
PASSWORD_AUTH_PAM_SERVICE_AC = "password-auth-ac"

FINGERPRINT_AUTH_PAM_SERVICE = "fingerprint-auth"
FINGERPRINT_AUTH_PAM_SERVICE_AC = "fingerprint-auth-ac"

SMARTCARD_AUTH_PAM_SERVICE = "smartcard-auth"
SMARTCARD_AUTH_PAM_SERVICE_AC = "smartcard-auth-ac"

PATH_SCSETUP = "/usr/bin/pkcs11_setup"

LDAP_CACERT_DOWNLOADED = "authconfig_downloaded.pem"

PATH_RPCBIND = "/sbin/rpcbind"
PATH_YPBIND = "/usr/sbin/ypbind"
PATH_ODDJOBD = "/usr/sbin/oddjobd"

PATH_KDMRC = "/usr/share/config/kdm/kdmrc"

LOGIC_REQUIRED = "required"
LOGIC_REQUISITE = "requisite"
LOGIC_SUFFICIENT = "sufficient"
LOGIC_OPTIONAL = "optional"
LOGIC_IGNORE_UNKNOWN = "[default=bad success=ok user_unknown=ignore]"
LOGIC_IGNORE_AUTH_ERR = "[default=bad success=ok auth_err=ignore user_unknown=ignore ignore=ignore]"
LOGIC_PKCS11 = "[success=done authinfo_unavail=ignore ignore=ignore default=die]"
LOGIC_FORCE_PKCS11 = "[success=done ignore=ignore default=die]"
LOGIC_PKCS11_KRB5 = "[success=ok authinfo_unavail=2 ignore=2 default=die]"
LOGIC_FORCE_PKCS11_KRB5 = "[success=ok ignore=2 default=die]"
LOGIC_SKIPNEXT = "[success=1 default=ignore]"
LOGIC_SKIPNEXT3 = "[success=3 default=ignore]"
LOGIC_ALWAYS_SKIP = "[default=1]"
LOGIC_SKIPNEXT_ON_FAILURE = "[default=1 success=ok]"


# Mandatory arguments for the various modules.
argv_unix_auth = [
    "try_first_pass"
]

argv_unix_password = [
    "try_first_pass",
    "use_authtok"
]

argv_afs_auth = [
    "use_first_pass"
]

argv_afs_password = [
    # It looks like current pam_afs (from OpenAFS 1.1.1) doesn't support
    # "use_authtok", so it'll probably interact badly with pam_pwquality,
    # but thanks to stack-traversal changes in Linux-PAM 0.75 and higher,
    # the password-changing should work anyway.
    "use_first_pass"
]

argv_pwquality_password = [
    "try_first_pass",
    "local_users_only",
    "retry=3",
    "authtok_type="
]

argv_passwdqc_password = [
    "enforce=users"
]

argv_eps_auth = [
    "use_first_pass"
]

argv_eps_password = [
    "use_authtok"
]

argv_fprintd_auth = [
]

argv_pkcs11_auth = [
    "nodebug"
]

argv_force_pkcs11_auth = [
    "nodebug",
    "wait_for_card"
]

argv_krb5_auth = [
    "use_first_pass"
]

argv_krb5_sc_auth = [
    "use_first_pass",
    "no_subsequent_prompt"
]

argv_krb5_password = [
    "use_authtok"
]

argv_ldap_auth = [
    "use_first_pass"
]

argv_ldap_password = [
    "use_authtok"
]

# This probably won't work straight-off because pam_unix won't give the right
# challenge, but what the heck.
argv_otp_auth = [
    "use_first_pass"
]

argv_succeed_if_auth = [
    "uid >=",
    "500",  # this must be the second arg - to be replaced
    "quiet_success"
]

argv_succeed_if_account = [
    "uid <",
    "500",  # this must be the second arg - to be replaced
    "quiet"
]

argv_succeed_if_session = [
    "service in crond",
    "quiet",
    "use_uid"
]

argv_succeed_if_nonlogin = [
    "service notin login:gdm:xdm:kdm:xscreensaver:gnome-screensaver:kscreensaver",
    "quiet",
    "use_uid"
]

argv_winbind_auth = [
    "use_first_pass"
]

argv_winbind_password = [
    "use_authtok"
]

argv_sss_auth = [
    "use_first_pass"
]

argv_sss_password = [
    "use_authtok"
]

argv_keyinit_session = [
    "revoke"
]

argv_ecryptfs_auth = [
    "unwrap"
]

argv_ecryptfs_password = [
    "unwrap"
]

argv_ecryptfs_session = [
    "unwrap"
]

argv_succeed_if_not_gdm = [
    "service !~ gdm*",
    "service !~ su*",
    "quiet"
]

argv_lastlog_gdm = [
    "nowtmp",
    "silent"
]

argv_lastlog_not_gdm = [
    "silent",
    "noupdate",
    "showfailed"
]

# Password hashing algorithms.
password_algorithms = ["descrypt", "bigcrypt", "md5", "sha256", "sha512"]

# for matching uid in succeeded if options
succ_if_re = re.compile(r'^.*[ \t]*uid[ \t]+(<|>=)[ \t]+([0-9]+)')


# Enumerations for PAM control flags and stack names.
(AUTH, ACCOUNT, SESSION, PASSWORD) = list(range(0, 4))

pam_stacks = ["auth", "account", "session", "password"]

(MANDATORY, STACK, LOGIC, NAME, ARGV) = list(range(0, 5))

(STANDARD, POSTLOGIN, PASSWORD_ONLY, FINGERPRINT, SMARTCARD) = list(range(0, 5))

pam_modules = [[] for service in (STANDARD, POSTLOGIN, PASSWORD_ONLY, FINGERPRINT, SMARTCARD)]

# The list of stacks, module flags, and arguments, if there are any.
# [ MANDATORY, STACK, LOGIC, NAME, ARGV ]
pam_modules[STANDARD] = [
    [True, AUTH, LOGIC_REQUIRED,
     "env", []],
    [False, AUTH, LOGIC_SKIPNEXT,
     "succeed_if", argv_succeed_if_nonlogin],
    [False, AUTH, LOGIC_PKCS11,
     "pkcs11", argv_pkcs11_auth],
    [False, AUTH, LOGIC_OPTIONAL,
     "krb5", argv_krb5_sc_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "permit", []],
    [False, AUTH, LOGIC_SUFFICIENT,
     "fprintd", []],
    [False, AUTH, LOGIC_SKIPNEXT_ON_FAILURE,
     "localuser", []],
    [True, AUTH, LOGIC_SUFFICIENT,
     "unix", argv_unix_auth],
    [False, AUTH, LOGIC_REQUISITE,
     "succeed_if", argv_succeed_if_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "sss", argv_sss_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "afs", argv_afs_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "afs.krb", argv_afs_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "eps_auth", argv_eps_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "krb5", argv_krb5_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "ldap", argv_ldap_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "otp", argv_otp_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "winbind", argv_winbind_auth],
    [True, AUTH, LOGIC_REQUIRED,
     "deny", []],
    # Account management is tricky.  Because we've implicitly committed to
    # getting it "right" for any combination of nss and pam, we have to be
    # careful about how we handle cases where networked sources of information
    # are unavailable.
    # At the very least, proper handling of password expiration depends on
    # this, and in the case of pam_ldap, we also may be depending on the
    # directory server for actual "is allowed to log in on this host" data.
    # The frequently-suggested method of using pam_localuser to short-circuit
    # pam_ldap may be only optional, but we can use pam_succeed_if
    # to short-circuit any network checks for *system* accounts
    # without allowing actual users in who should be legitimately denied by
    # LDAP (if not overriden by enabling the optional pam_localuser).
    # Because we'd now be ending the stack with sufficient modules, and PAM's
    # behavior isn't defined if none of them return success, we add a
    # successful call to pam_permit at the end as a requirement.
    [False, ACCOUNT, LOGIC_REQUIRED,
     "access", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "unix", []],
    [False, ACCOUNT, LOGIC_SUFFICIENT,
     "localuser", []],
    [True, ACCOUNT, LOGIC_SUFFICIENT,
     "succeed_if", argv_succeed_if_account],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "sss", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "ldap", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "krb5", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "winbind", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "permit", []],
    [False, PASSWORD, LOGIC_REQUISITE,
     "pwquality", argv_pwquality_password],
    [False, PASSWORD, LOGIC_REQUISITE,
     "passwdqc", argv_passwdqc_password],
    [True, PASSWORD, LOGIC_SUFFICIENT,
     "unix", argv_unix_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "sss", argv_sss_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "afs", argv_afs_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "afs.krb", argv_afs_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "eps_passwd", argv_eps_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "krb5", argv_krb5_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "ldap", argv_ldap_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "winbind", argv_winbind_password],
    [True, PASSWORD, LOGIC_REQUIRED,
     "deny", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "keyinit", argv_keyinit_session],
    [True, SESSION, LOGIC_REQUIRED,
     "limits", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "systemd", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "mkhomedir", []],
    [True, SESSION, LOGIC_SKIPNEXT,
     "succeed_if", argv_succeed_if_session],
    [True, SESSION, LOGIC_REQUIRED,
     "unix", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "sss", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs.krb", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "krb5", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "ldap", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "winbind", []]
]

pam_modules[POSTLOGIN] = [
    [False, AUTH, LOGIC_OPTIONAL,
     "ecryptfs", argv_ecryptfs_auth],
    [False, PASSWORD, LOGIC_OPTIONAL,
     "ecryptfs", argv_ecryptfs_password],
    [False, SESSION, LOGIC_OPTIONAL,
     "ecryptfs", argv_ecryptfs_session],
    [True, SESSION, LOGIC_SKIPNEXT,
     "succeed_if", argv_succeed_if_not_gdm],
    [True, SESSION, LOGIC_ALWAYS_SKIP,
     "lastlog", argv_lastlog_gdm],
    [True, SESSION, LOGIC_OPTIONAL,
     "lastlog", argv_lastlog_not_gdm],
]

pam_modules[PASSWORD_ONLY] = [
    [True, AUTH, LOGIC_REQUIRED,
     "env", []],
    [False, AUTH, LOGIC_REQUIRED,
     "deny", []],
    [False, AUTH, LOGIC_SKIPNEXT_ON_FAILURE,
     "localuser", []],
    [True, AUTH, LOGIC_SUFFICIENT,
     "unix", argv_unix_auth],
    [False, AUTH, LOGIC_REQUISITE,
     "succeed_if", argv_succeed_if_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "sss", argv_sss_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "afs", argv_afs_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "afs.krb", argv_afs_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "eps_auth", argv_eps_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "krb5", argv_krb5_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "ldap", argv_ldap_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "otp", argv_otp_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "winbind", argv_winbind_auth],
    [True, AUTH, LOGIC_REQUIRED,
     "deny", []],
    [False, ACCOUNT, LOGIC_REQUIRED,
     "access", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "unix", []],
    [False, ACCOUNT, LOGIC_SUFFICIENT,
     "localuser", []],
    [True, ACCOUNT, LOGIC_SUFFICIENT,
     "succeed_if", argv_succeed_if_account],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "sss", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "ldap", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "krb5", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "winbind", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "permit", []],
    [False, PASSWORD, LOGIC_REQUISITE,
     "pwquality", argv_pwquality_password],
    [False, PASSWORD, LOGIC_REQUISITE,
     "passwdqc", argv_passwdqc_password],
    [True, PASSWORD, LOGIC_SUFFICIENT,
     "unix", argv_unix_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "sss", argv_sss_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "afs", argv_afs_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "afs.krb", argv_afs_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "eps_passwd", argv_eps_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "krb5", argv_krb5_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "ldap", argv_ldap_password],
    [False, PASSWORD, LOGIC_SUFFICIENT,
     "winbind", argv_winbind_password],
    [True, PASSWORD, LOGIC_REQUIRED,
     "deny", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "keyinit", argv_keyinit_session],
    [True, SESSION, LOGIC_REQUIRED,
     "limits", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "systemd", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "mkhomedir", []],
    [True, SESSION, LOGIC_SKIPNEXT,
     "succeed_if", argv_succeed_if_session],
    [True, SESSION, LOGIC_REQUIRED,
     "unix", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "sss", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs.krb", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "krb5", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "ldap", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "winbind", []]
]

pam_modules[FINGERPRINT] = [
    [True, AUTH, LOGIC_REQUIRED,
     "env", []],
    [False, AUTH, LOGIC_REQUIRED,
     "deny", []],
    [False, AUTH, LOGIC_SUFFICIENT,
     "fprintd", []],
    [True, AUTH, LOGIC_REQUIRED,
     "deny", []],
    [False, ACCOUNT, LOGIC_REQUIRED,
     "access", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "unix", []],
    [False, ACCOUNT, LOGIC_SUFFICIENT,
     "localuser", []],
    [True, ACCOUNT, LOGIC_SUFFICIENT,
     "succeed_if", argv_succeed_if_account],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "sss", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "ldap", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "krb5", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "winbind", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "permit", []],
    [True, PASSWORD, LOGIC_REQUIRED,
     "deny", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "keyinit", argv_keyinit_session],
    [True, SESSION, LOGIC_REQUIRED,
     "limits", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "systemd", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "mkhomedir", []],
    [True, SESSION, LOGIC_SKIPNEXT,
     "succeed_if", argv_succeed_if_session],
    [True, SESSION, LOGIC_REQUIRED,
     "unix", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "sss", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs.krb", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "krb5", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "ldap", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "winbind", []]
]

pam_modules[SMARTCARD] = [
    [True, AUTH, LOGIC_REQUIRED,
     "env", []],
    [False, AUTH, LOGIC_PKCS11,
     "pkcs11", argv_force_pkcs11_auth],
    [False, AUTH, LOGIC_OPTIONAL,
     "krb5", argv_krb5_sc_auth],
    [False, AUTH, LOGIC_SUFFICIENT,
     "permit", []],
    [True, AUTH, LOGIC_REQUIRED,
     "deny", []],
    [False, ACCOUNT, LOGIC_REQUIRED,
     "access", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "unix", []],
    [False, ACCOUNT, LOGIC_SUFFICIENT,
     "localuser", []],
    [True, ACCOUNT, LOGIC_SUFFICIENT,
     "succeed_if", argv_succeed_if_account],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "sss", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "ldap", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "krb5", []],
    [False, ACCOUNT, LOGIC_IGNORE_UNKNOWN,
     "winbind", []],
    [True, ACCOUNT, LOGIC_REQUIRED,
     "permit", []],
    [False, PASSWORD, LOGIC_REQUIRED,
     "pkcs11", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "keyinit", argv_keyinit_session],
    [True, SESSION, LOGIC_REQUIRED,
     "limits", []],
    [True, SESSION, LOGIC_OPTIONAL,
     "systemd", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "mkhomedir", []],
    [True, SESSION, LOGIC_SKIPNEXT,
     "succeed_if", argv_succeed_if_session],
    [True, SESSION, LOGIC_REQUIRED,
     "unix", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "sss", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "afs.krb", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "krb5", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "ldap", []],
    [False, SESSION, LOGIC_OPTIONAL,
     "winbind", []]
]


class SysVInitService:
    def start(self, service):
        os.system("/sbin/service " + service + " start")

    def stop(self, service):
        os.system("/sbin/service " + service + " stop >/dev/null 2>&1")

    def enable(self, service):
        os.system("/sbin/chkconfig --add " + service)
        os.system("/sbin/chkconfig --level 345 " + service + " on")

    def disable(self, service):
        os.system("/sbin/chkconfig --level 345 " + service + " off")

    def isEnabled(self, service):
        rv = os.system("/sbin/chkconfig " + service + " >/dev/null 2>&1")
        return os.WIFEXITED(rv) and os.WEXITSTATUS(rv) == 0

    def tryRestart(self, service):
        os.system("/sbin/service " + service + " condrestart >/dev/null 2>&1")


class SystemdService:
    def start(self, service):
        os.system("/bin/systemctl start " + service + ".service")

    def stop(self, service):
        os.system("/bin/systemctl stop " + service + ".service >/dev/null 2>&1")

    def enable(self, service):
        os.system("/bin/systemctl enable " + service + ".service >/dev/null 2>&1")

    def disable(self, service):
        os.system("/bin/systemctl disable " + service + ".service >/dev/null 2>&1")

    def isEnabled(self, service):
        rv = os.system("/bin/systemctl is-enabled " + service + ".service >/dev/null 2>&1")
        return os.WIFEXITED(rv) and os.WEXITSTATUS(rv) == 0

    def tryRestart(self, service):
        os.system("/bin/systemctl try-restart " + service + ".service >/dev/null 2>&1")


try:
    if "systemd" in os.readlink("/sbin/init"):
        Service = SystemdService()
    else:
        Service = SysVInitService()
except OSError:
    Service = SysVInitService()


class SafeFile:
    def __init__(self, filename, default_mode):
        (base, name) = os.path.split(filename)
        self.missing = False
        self.file = tempfile.NamedTemporaryFile(dir=base, prefix=name, delete=True)
        # overwrite the inode attributes and contents
        if call(["/bin/cp", "-af", filename, self.file.name],
                stderr=os.open('/dev/null', os.O_WRONLY)) == 1:
            self.missing = True
            # the mode was not copied, use the default
            os.fchmod(self.file.fileno(), default_mode)
        self.filename = filename

    def save(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        os.rename(self.file.name, self.filename)
        if self.missing:
            call([paths.RESTORECON, self.filename],
                 stderr=os.open('/dev/null', os.O_WRONLY))

    def close(self):
        # we may have renamed the temp file, need to catch OSError
        try:
            self.file.close()
        except OSError:
            pass

    def write(self, s):
        return self.file.write(s)

    def rewind(self):
        self.file.seek(0)
        self.file.truncate(0)


class FileBackup:
    def __init__(self, backupname, origpath):
        self.backupName = backupname
        self.origPath = origpath

    def safeCopy(self, src, dest):
        rv = True
        srcfd = None
        destfile = None

        try:
            srcfd = openfdLocked(src, os.O_RDONLY, 0)
        except IOError:
            return True
        try:
            mode = stat.S_IMODE(os.fstat(srcfd).st_mode)
        except (IOError, OSError):
            os.close(srcfd)
            return True

        try:
            destfile = SafeFile(dest, mode)
            destfile.rewind()
        except IOError:
            rv = False
        try:
            while rv:
                b = os.read(srcfd, 4096)
                if not b:
                    rv = True
                    break
                os.write(destfile.file.fileno(), b)
        except (IOError, OSError):
            rv = False
        try:
            if srcfd:
                os.close(srcfd)
        except (IOError, OSError):
            pass
        try:
            if destfile and rv:
                destfile.save()
                destfile.close()
        except (IOError, OSError):
            rv = False
        return rv

    def backup(self, destdir):
        rv = True
        try:
            if not os.path.isdir(destdir):
                os.mkdir(destdir)
        except (OSError, IOError):
            rv = False

        backuppath = destdir + "/" + self.backupName
        if rv:
            rv = self.safeCopy(self.origPath,
                               backuppath)

        return rv

    def restore(self, backupdir):
        rv = True
        try:
            if not os.path.isdir(backupdir):
                return False
        except (IOError, OSError):
            rv = False

        backuppath = backupdir + "/" + self.backupName
        if rv and os.path.isfile(backuppath):
            rv = self.safeCopy(backuppath, self.origPath)

        try:
            if rv:
                call([paths.RESTORECON, self.origPath],
                     stderr=os.open(paths.DEV_NULL, os.O_WRONLY))
        except (IOError, OSError):
            pass

        return rv


class CacheBackup(FileBackup):
    def backup(self, destdir):
        rv = True
        try:
            if not os.path.isdir(destdir):
                os.mkdir(destdir)
        except (OSError, IOError):
            rv = False

        backuppath = destdir + "/" + self.backupName
        if rv:
            dest = None
            try:

                enabled = readCache()
                dest = open(backuppath, "w")
                dest.write(str(int(enabled)))
            except IOError:
                rv = False
            if dest:
                dest.close()

        if not rv:
            try:
                os.unlink(backuppath)
            except OSError:
                pass
        return rv

    def restore(self, backupdir):
        rv = True
        try:
            if not os.path.isdir(backupdir):
                return False
        except (IOError, OSError):
            rv = False

        backuppath = backupdir + "/" + self.backupName
        if rv and os.path.isfile(backuppath):
            backup = None
            try:
                backup = open(backuppath, "r")
                enabled = int(backup.read())
                writeCache(enabled)
            except (IOError, OSError, ValueError):
                rv = False
            if backup:
                backup.close()

        return rv


# indexes for configs
(CFG_NSSWITCH, CFG_PAM, CFG_POSTLOGIN_PAM, CFG_NETWORK,
 CFG_SSSD, CFG_NSSLDAP, CFG_NSLCD, CFG_PAMLDAP, CFG_OPENLDAP,
 CFG_KRB5, CFG_CACHE, CFG_PASSWORD_PAM, CFG_FINGERPRINT_PAM,
 CFG_SMARTCARD_PAM) = list(range(0, 14))

all_configs = [
    FileBackup("nsswitch.conf", SYSCONFDIR + "/nsswitch.conf"),
    FileBackup("system-auth-ac", SYSCONFDIR + "/pam.d/" + AUTH_PAM_SERVICE_AC),
    FileBackup("postlogin-ac", SYSCONFDIR + "/pam.d/" + POSTLOGIN_PAM_SERVICE_AC),
    FileBackup("network", SYSCONFDIR + "/sysconfig/network"),
    FileBackup("sssd.conf", PATH_SSSD_CONFIG),
    FileBackup("nss_ldap.conf", SYSCONFDIR + "/nss_ldap.conf"),
    FileBackup("nslcd.conf", SYSCONFDIR + "/nslcd.conf"),
    FileBackup("pam_ldap.conf", SYSCONFDIR + "/pam_ldap.conf"),
    FileBackup("openldap.conf", SYSCONFDIR + "/openldap/ldap.conf"),
    FileBackup("krb5.conf", SYSCONFDIR + "/krb5.conf"),
    CacheBackup("cacheenabled.conf", ""),
    FileBackup("password-auth-ac", SYSCONFDIR + "/pam.d/" + PASSWORD_AUTH_PAM_SERVICE_AC),
    FileBackup("fingerprint-auth-ac", SYSCONFDIR + "/pam.d/" + FINGERPRINT_AUTH_PAM_SERVICE_AC),
    FileBackup("smartcard-auth-ac", SYSCONFDIR + "/pam.d/" + SMARTCARD_AUTH_PAM_SERVICE_AC)
]

sssd_options = [
    ('ldapServer', 'ldap_uri'),
    ('ldapBaseDN', 'ldap_search_base'),
    ('enableLDAPS', 'ldap_id_use_start_tls'),
    ('ldapSchema', 'ldap_schema'),
    ('ldapCacertDir', 'ldap_tls_cacertdir'),
    ('kerberosKDC', 'krb5_server'),
    ('kerberosAdminServer', 'krb5_kpasswd'),
    ('kerberosRealm', 'krb5_realm'),
    ('enableCacheCreds', 'cache_credentials'),
    ('enableCacheCreds', 'krb5_store_password_if_offline')
]


class Options:
    def __init__(self):
        self.enablesssd = False
        self.enablesssdauth = False
        self.enableldap = False
        self.enableforcelegacy = False
        self.enablemkhomedir = False
        self.enablekrb5 = False
        self.nostart = False
        self.disableldap = False
        self.disablekrb5 = False
        self.disablesssd = False
        self.disablesssdauth = False
        self.disablemkhomedir = False


def kdmTheme(useTheme=True):
    bp = PATH_KDMRC + ".ipabp"
    try:
        os.rename(PATH_KDMRC, bp)
        with open(PATH_KDMRC, 'w') as kdm:
            for line in open(bp):
                if "UseTheme=" in line:
                    if useTheme:
                        kdm.write("UseTheme=true\n")
                    else:
                        kdm.write("UseTheme=false\n")
                else:
                    kdm.write(line)
    except OSError:
        print >> sys.stderr, ("Something wrong with kdmrc " +
                              "configuring. Check it manually.")


class AuthConfig:
    def __init__(self):
        # self.nis_avail = False
        self.kerberos_avail = False
        self.ldap_avail = False
        self.sssd_avail = False
        self.options = Options()
        self.info = None
        self.pristineinfo = None
        self.retval = 0

    def print_error(self, error):
        sys.stderr.write("%s: %s\n" % (self.module(), error))

    def module(self):
        return "authconfig"

    def run(self):
        if os.getuid() != 0:
            self.print_error("can only be run as root")
            sys.exit(2)
        self.readAuthInfo()
        self.testAvailableSubsys()
        self.overrideSettings()
        self.writeAuthInfo()
        return self.retval

    def readAuthInfo(self):
        self.info = read(self.print_error)
        self.pristineinfo = self.info.copy()
        if self.info.enableLocAuthorize == None:
            self.info.enableLocAuthorize = True  # ON by default

    def testAvailableSubsys(self):
        # self.nis_avail = (os.access(authinfo.PATH_YPBIND, os.X_OK) and
        #                   os.access(authinfo.PATH_LIBNSS_NIS, os.X_OK))
        self.kerberos_avail = os.access(PATH_PAM_KRB5, os.X_OK)
        self.ldap_avail = (os.access(PATH_PAM_LDAP, os.X_OK) and
                           os.access(PATH_LIBNSS_LDAP, os.X_OK))
        self.sssd_avail = (os.access(PATH_PAM_SSS, os.X_OK) and
                           os.access(PATH_LIBNSS_SSS, os.X_OK))
        self.cache_avail = os.access(PATH_NSCD, os.X_OK)
        self.fprintd_avail = os.access(PATH_PAM_FPRINTD, os.X_OK)

    def overrideSettings(self):
        bool_settings = {"shadow": "enableShadow",
                         "locauthorize": "enableLocAuthorize",
                         "pamaccess": "enablePAMAccess",
                         "mkhomedir": "enableMkHomeDir",
                         "cache": "enableCache",
                         "ecryptfs": "enableEcryptfs",
                         "hesiod": "enableHesiod",
                         "ldap": "enableLDAP",
                         "ldaptls": "enableLDAPS",
                         "ldapauth": "enableLDAPAuth",
                         "krb5": "enableKerberos",
                         "nis": "enableNIS",
                         "krb5kdcdns": "kerberosKDCviaDNS",
                         "krb5realmdns": "kerberosRealmviaDNS",
                         "smartcard": "enableSmartcard",
                         "fingerprint": "enableFprintd",
                         "requiresmartcard": "forceSmartcard",
                         "winbind": "enableWinbind",
                         "winbindauth": "enableWinbindAuth",
                         "winbindkrb5": "winbindKrb5",
                         "ipav2": "enableIPAv2",
                         "wins": "enableWINS",
                         "sssd": "enableSSSD",
                         "sssdauth": "enableSSSDAuth",
                         "forcelegacy": "enableForceLegacy",
                         "cachecreds": "enableCacheCreds",
                         "preferdns": "preferDNSinHosts"}

        string_settings = {"passalgo": "passwordAlgorithm",
                           "ldapserver": "ldapServer",
                           "ldapbasedn": "ldapBaseDN",
                           "ldaploadcacert": "ldapCacertURL",
                           "krb5realm": "kerberosRealm",
                           "krb5kdc": "kerberosKDC",
                           "krb5adminserver": "kerberosAdminServer",
                           "nisdomain": "nisDomain",
                           "nisserver": "nisServer",
                           "ipav2domain": "ipav2Domain",
                           "ipav2realm": "ipav2Realm",
                           "ipav2server": "ipav2Server"}

        for opt, aival in bool_settings.items():
            try:
                enable = getattr(self.options, "enable" + opt)
            except AttributeError:
                pass
            else:
                if enable:
                    setattr(self.info, aival, True)

            try:
                disable = getattr(self.options, "disable" + opt)
            except AttributeError:
                pass
            else:
                if disable:
                    setattr(self.info, aival, False)

        try:
            self.info.ldapSchema = ''
        except AttributeError:
            pass

        for opt, aival in string_settings.items():
            try:
                if getattr(self.options, opt) is not None:
                    setattr(self.info, aival, getattr(self.options, opt))
            except AttributeError:
                pass

    def writeAuthInfo(self):
        self.info.testLDAPCACerts()
        if self.info.ldapCacertURL:
            if not self.info.downloadLDAPCACert():
                self.retval = 4
        # There is no cacertdir_rehash script.
        # self.info.rehashLDAPCACerts()
        if not self.info.writeChanged(self.pristineinfo):
            self.retval = 6
        # Ensure oddjobd.services toggled.
        if self.options.enablemkhomedir:
            self.info.toggleOddjobService(nostart=False)

        # kdmrc tweak.
        if self.options.enablesssdauth or self.options.enableldap:
            kdmTheme(False)
        elif self.options.disablesssdauth or self.options.disableldap:
            kdmTheme(True)


def stringsDiffer(a, b, case_sensitive):
    if not a and not b:
        return False
    if not a or not b:
        return True
    if case_sensitive:
        return a != b
    else:
        return a.lower() != b.lower()


class SaveGroup:
    def __init__(self, savefunc, togglefunc, attrlist):
        self.saveFunction = savefunc
        self.toggleFunction = togglefunc
        self.attrlist = attrlist

    def attrsDiffer(self, a, b):
        for (aname, atype) in self.attrlist:
            if aname in a.inconsistentAttrs:
                return True
            if atype == "b":
                if getattr(a, aname) != getattr(b, aname):
                    return True
            elif atype == "c":
                if stringsDiffer(getattr(a, aname), getattr(b, aname), True):
                    return True
            elif atype == "i":
                if stringsDiffer(getattr(a, aname), getattr(b, aname), False):
                    return True
        return False


class AuthInfo:
    def __init__(self, msgcb):
        self.messageCB = msgcb
        self.inconsistentAttrs = []

        self.nisLocalDomain = ""
        self.ldapServer = ""
        self.ldapBaseDN = ""

        self.kerberosRealm = ""
        self.kerberosRealmviaDNS = None
        self.kerberosKDC = ""
        self.kerberosKDCviaDNS = None
        self.kerberosAdminServer = ""

        self.nisServer = ""
        self.nisDomain = ""
        self.nisLocalDomain = ""

        # nsswitch.conf setup.
        self.enableCache = None
        self.enableWINS = None
        self.enableMDNS = None
        self.enableMyhostname = None
        self.preferDNSinHosts = None
        self.enableSSSD = None
        self.enableCompat = None
        self.enableDB = None
        self.enableDirectories = None
        self.enableHesiod = None
        self.enableLDAP = None
        self.enableLDAPS = None
        self.enableNIS = None
        self.enableNIS3 = None
        self.enableAltfiles = None
        self.enableWinbind = None
        self.enableIPAv2 = None
        self.enableOdbcbind = None
        self.enableLDAPbind = None
        self.enableHesiodbind = None
        self.enableDBbind = None
        self.enableDBIbind = None

        # Authentication setup.
        self.enablePWQuality = None
        self.enableEcryptfs = None
        self.enableKerberos = None
        self.enableLDAPAuth = None
        self.enableSmartcard = None
        self.forceSmartcard = None
        self.enableFprintd = None
        self.implicitSSSD = False
        self.implicitSSSDAuth = False
        self.enablePasswdQC = None
        self.enableWinbindAuth = None
        self.enablePAMAccess = None
        self.enableMkHomeDir = None
        self.enableLocAuthorize = None
        self.passwordAlgorithm = ""
        self.algoRounds = ""
        self.enableShadow = None
        self.enableNullOk = True
        self.brokenShadow = None
        self.forceBrokenShadow = None
        self.enableSSSDAuth = None
        self.enableForceLegacy = None
        self.enableCacheCreds = None
        self.winbindKrb5 = None
        self.enableAFS = None
        self.enableAFSKerberos = None
        self.enableEPS = None
        self.enableOTP = None
        self.enableSysNetAuth = None
        self.uidMin = None
        self.winbindOffline = None

        # Not an options.
        self.pwqualityArgs = ""
        self.passwdqcArgs = ""
        self.pamAccessArgs = ""
        self.mkhomedirArgs = "umask=0077"
        self.localuserArgs = ""
        self.systemdArgs = ""
        self.ldapCacertDir = ""
        self.ldapCacertURL = ""
        self.ldapSchema = ""

        self.smbSecurity = ""
        self.smbRealm = ""
        self.smbServers = ""

        self.ipaDomainJoined = False

        self.smartcardModule = ""
        self.smartcardAction = ""

        self.pamLinked = True

        global SSSDConfig
        self.sssdConfig = None
        self.sssdDomain = None
        self.forceSSSDUpdate = None
        if SSSDConfig:
            try:
                self.sssdConfig = SSSDConfig.SSSDConfig()
                self.sssdConfig.new_config()
            except IOError:
                pass

        self.toggleFunctions = set()
        self.save_groups = [
            SaveGroup(self.writeCache, self.toggleCachingService, [("enableCache", "b"), ("implicitSSSD", "b")]),
            SaveGroup(self.writeLDAP, None, [("ldapServer", "i"), ("ldapBaseDN", "c"), ("enableLDAPS", "b"),
                                             ("ldapSchema", "c"), ("ldapCacertDir", "c"), ("passwordAlgorithm", "i")]),
            SaveGroup(self.writeKerberos, None, [("kerberosRealm", "c"), ("kerberosKDC", "i"),
                                                 ("smbSecurity", "i"), ("smbRealm", "c"), ("smbServers", "i"),
                                                 ("kerberosAdminServer", "i"), ("kerberosRealmviaDNS", "b"),
                                                 ("kerberosKDCviaDNS", "b")]),
            SaveGroup(self.writeSSSD, self.toggleSSSDService,
                      [("ldapServer", "i"), ("ldapBaseDN", "c"), ("enableLDAPS", "b"),
                       ("ldapSchema", "c"), ("ldapCacertDir", "c"), ("enableCacheCreds", "b"),
                       ("kerberosRealm", "c"), ("kerberosKDC", "i"), ("kerberosAdminServer", "i"),
                       ("forceSSSDUpdate", "b"), ("enableLDAP", "b"), ("enableKerberos", "b"),
                       ("enableLDAPAuth", "b"), ("enableIPAv2", "b")]),
            SaveGroup(self.writeNSS, None, [("enableDB", "b"), ("enableDirectories", "b"), ("enableWinbind", "b"),
                                            ("enableOdbcbind", "b"), ("enableNIS3", "b"), ("enableNIS", "b"),
                                            ("enableLDAPbind", "b"), ("enableLDAP", "b"), ("enableHesiodbind", "b"),
                                            ("enableHesiod", "b"), ("enableDBIbind", "b"), ("enableDBbind", "b"),
                                            ("enableCompat", "b"), ("enableWINS", "b"), ("enableMDNS", "b"),
                                            ("enableMyhostname", "b"),
                                            ("enableNIS3", "b"), ("enableNIS", "b"), ("enableIPAv2", "b"),
                                            ("enableSSSD", "b"), ("preferDNSinHosts", "b"), ("implicitSSSD", "b")]),
            SaveGroup(self.writePAM, None, [("pwqualityArgs", "c"), ("passwdqcArgs", "c"),
                                            ("localuserArgs", "c"), ("pamAccessArgs", "c"), ("enablePAMAccess", "b"),
                                            ("mkhomedirArgs", "c"), ("enableMkHomeDir", "b"), ("algoRounds", "c"),
                                            ("passwordAlgorithm", "i"), ("enableShadow", "b"), ("enableNIS", "b"),
                                            ("enableNullOk", "b"), ("forceBrokenShadow", "b"), ("enableLDAPAuth", "b"),
                                            ("enableKerberos", "b"), ("enableSmartcard", "b"), ("forceSmartcard", "b"),
                                            ("enableWinbindAuth", "b"), ("enableMkHomeDir", "b"), ("enableAFS", "b"),
                                            ("enableAFSKerberos", "b"), ("enablePWQuality", "b"), ("enableEPS", "b"),
                                            ("enableEcryptfs", "b"), ("enableOTP", "b"), ("enablePasswdQC", "b"),
                                            ("enableLocAuthorize", "b"), ("enableSysNetAuth", "b"),
                                            ("winbindOffline", "b"), ("winbindKrb5", "b"),
                                            ("enableSSSDAuth", "b"), ("enableFprintd", "b"), ("pamLinked", "b"),
                                            ("implicitSSSDAuth", "b"), ("systemdArgs", "c"), ("uidMin", "i"),
                                            ("enableIPAv2", "b")]),
            SaveGroup(self.writeNetwork, None, [("nisDomain", "c")]),
            SaveGroup(None, self.toggleNisService, [("enableNIS", "b")]),
            SaveGroup(None, self.toggleOddjobService, [("enableMkHomeDir", "b")]),
            SaveGroup(None, self.toggleLDAPService, [("enableLDAP", "b"), ("enableLDAPAuth", "b"),
                                                     ("implicitSSSD", "b"), ("implicitSSSDAuth", "b"),
                                                     ("enableForceLegacy", "b")]),
            SaveGroup(None, self.toggleSSSDService, [("implicitSSSD", "b"), ("implicitSSSDAuth", "b"),
                                                     ("enableIPAv2", "b"), ("enableSSSD", "b"), ("enableSSSDAuth", "b"),
                                                     ("enableForceLegacy", "b")])
        ]


    def copy(self):
            ret = copy.copy(self)
            ret.joinUser = ""
            ret.joinPassword = ""
            return ret

    def update(self, validate=False):
        self.kerberosKDC = cleanList(self.kerberosKDC)
        self.kerberosAdminServer = cleanList(self.kerberosAdminServer)
        self.ldapServer = self.ldapHostsToURIs(self.ldapServer, validate)
        if self.enableCacheCreds is None:
            self.enableCacheCreds = True  # enabled by default

    def read(self):
        ref = self.copy()
        self.readNSS(ref)
        self.readPAM(ref)

        reallyimplicit = self.sssdSupported()
        if self.implicitSSSD and not reallyimplicit and not self.enableIPAv2:
            self.setParam("enableSSSD", True, ref)
        if self.implicitSSSDAuth and not reallyimplicit and not self.enableIPAv2:
            self.setParam("enableSSSDAuth", True, ref)

        self.readNetwork(ref)
        # if SSSD not implicitely enabled
        if not self.implicitSSSD and not self.implicitSSSDAuth:
            self.readSSSD(ref)
        self.readLDAP(ref)
        self.readKerberos(ref)
        if self.implicitSSSD or self.implicitSSSDAuth:
            self.readSSSD(ref)
        self.readCache(ref)
        self.update()

    # Read whether or not caching is enabled.
    def readCache(self, ref):
        self.setParam("enableCache", readCache(), ref)
        return True

    # Read NSS setup from /etc/nsswitch.conf.
    def readNSS(self, ref):
        # Open the file.  Bail if it's not there or there's some problem
        # reading it.
        nssconfig = ""
        try:
            f = open(all_configs[CFG_NSSWITCH].origPath, "r")
        except IOError:
            return False

        for line in f:
            line = line.strip()

            value = matchKey(line, "passwd:")
            if value:
                nssconfig = value
            else:
                # wins can be found in hosts only
                value = matchKey(line, "hosts:")
                if value:
                    if checkNSS(value, "wins"):
                        self.setParam("enableWINS", True, ref)
                    if checkNSS(value, "mdns4_minimal [NOTFOUND=return]"):
                        self.setParam("enableMDNS", True, ref)
                    if checkNSS(value, "myhostname"):
                        self.setParam("enableMyhostname", True, ref)

                    nispos = checkNSS(value, "nis")
                    if nispos is None:
                        nispos = checkNSS(value, "wins")
                    dnspos = checkNSS(value, "dns")
                    if nispos is not None and dnspos is not None:
                        self.setParam("preferDNSinHosts", dnspos < nispos, ref)

        if nssconfig:
            nssmap = (('Compat', 'compat'), ('DB', 'db'),
                      ('Directories', 'directories'), ('Hesiod', 'hesiod'),
                      ('LDAP', 'ldap'), ('NIS', 'nis'), ('Altfiles', 'altfiles'),
                      ('NIS3', 'nisplus'), ('Winbind', 'winbind'))
            for attr, nssentry in nssmap:
                if checkNSS(nssconfig, nssentry):
                    self.setParam('enable' + attr, True, ref)

            self.setParam("implicitSSSD", bool(checkNSS(nssconfig, "sss")), ref)
        f.close()
        return True

    def setParam(self, attr, value, ref):
        oldval = getattr(self, attr)
        if oldval != value:
            setattr(self, attr, value)
            if oldval != getattr(ref, attr):
                self.inconsistentAttrs.append(attr)

    # Read hints from the PAM control file.
    def readPAM(self, ref):
        # Open the system-auth file.  Bail if it's not there or
        # there's some problem reading it.
        try:
            f = open(all_configs[CFG_PAM].origPath, "r")
        except IOError:
            try:
                f = open(SYSCONFDIR + "/pam.d/" + AUTH_PAM_SERVICE, "r")
            except IOError:
                return False

        self.readPAMFile(ref, f)
        f.close()

        # Open the postlogin file.  It's ok if it's not there.
        try:
            f = open(all_configs[CFG_POSTLOGIN_PAM].origPath, "r")
        except IOError:
            try:
                f = open(SYSCONFDIR + "/pam.d/" + POSTLOGIN_PAM_SERVICE, "r")
            except IOError:
                return True

        self.readPAMFile(ref, f)
        f.close()
        return True

    def readPAMFile(self, ref, f):
        prevline = ""
        for line in f:
            lst = line.split("#", 1)
            if len(lst) > 1:
                line = lst[0]

            line = line.rstrip()
            # Join lines ending with "\\"
            if line[-1:] == "\\":
                prevline += line[:-1] + " "
                continue
            line = prevline + line
            prevline = ""
            line = line.lstrip()

            args = ""

            lst = line.split(None, 1)
            if len(lst) < 2:
                continue
            (stack, line) = lst

            if (stack != "auth" and stack != "account"
                and stack != "password" and stack != "session"):
                continue

            if line.startswith("["):
                lst = line.split("]", 1)
            else:
                lst = line.split(None, 1)

            if len(lst) < 2:
                continue

            if lst[0] == "include":
                continue

            control = lst[0]
            if control.startswith("["):
                control += "]"

            line = lst[1]

            lst = line.split(None, 1)

            if len(lst) < 1:
                continue
            (module,) = lst[0].split("/")[-1:]

            if len(lst) == 2:
                args = lst[1]

            if module.startswith("pam_cracklib") or module.startswith("pam_pwquality"):
                self.setParam("enablePWQuality", True, ref)
                if args:
                    self.setParam("pwqualityArgs", args, ref)
                continue
            if module.startswith("pam_ecryptfs"):
                self.setParam("enableEcryptfs", True, ref)
                continue
            if module.startswith("pam_krb5"):
                self.setParam("enableKerberos", True, ref)
                continue
            if module.startswith("pam_ldap"):
                self.setParam("enableLDAPAuth", True, ref)
                continue
            if module.startswith("pam_pkcs11"):
                self.setParam("enableSmartcard", True, ref)
                if "authinfo_unavail" not in control:
                    self.setParam("forceSmartcard", True, ref)
                else:
                    self.setParam("forceSmartcard", False, ref)
                continue
            if module.startswith("pam_fprintd"):
                self.setParam("enableFprintd", True, ref)
                continue
            if module.startswith("pam_passwdqc"):
                self.setParam("enablePasswdQC", True, ref)
                if args:
                    self.setParam("passwdqcArgs", args, ref)
                continue
            if module.startswith("pam_winbind"):
                self.setParam("enableWinbindAuth", True, ref)
                self.setParam("winbindKrb5", args.find("krb5_auth") >= 0, ref)
                continue
            if module.startswith("pam_sss"):
                self.setParam("implicitSSSDAuth", True, ref)
                continue
            if module.startswith("pam_access"):
                self.setParam("enablePAMAccess", True, ref)
                if args:
                    self.setParam("pamAccessArgs", args, ref)
                continue
            if module.startswith("pam_mkhomedir") or module.startswith("pam_oddjob_mkhomedir"):
                self.setParam("enableMkHomeDir", True, ref)
                if args:
                    # first place where we are setting them
                    self.mkhomedirArgs = args
                continue
            if module.startswith("pam_localuser"):
                self.setParam("enableLocAuthorize", True, ref)
                if args:
                    self.setParam("localuserArgs", args, ref)
                continue
            if module.startswith("pam_systemd"):
                if args:
                    self.setParam("systemdArgs", args, ref)
                continue
            if stack == "password":
                if module.startswith("pam_unix"):
                    for algo in password_algorithms:
                        if args.find(algo) >= 0:
                            self.setParam("passwordAlgorithm", algo, ref)
                    try:
                        ridx = args.index("rounds=")
                        rounds = args[ridx + 7:].split(None, 1)
                        self.setParam("algoRounds", str(int(rounds[0])), ref)
                    except (ValueError, IndexError):
                        pass
                    try:
                        os.stat("/etc/shadow")
                        self.setParam("enableShadow", True, ref)
                    except OSError:
                        self.setParam("enableShadow", False, ref)
            if stack == "auth":
                if module.startswith("pam_unix"):
                    self.setParam("enableNullOk", args.find("nullok") >= 0, ref)
            if stack == "account":
                if module.startswith("pam_unix"):
                    self.setParam("brokenShadow", args.find("broken_shadow") >= 0, ref)
            if stack == "auth" or stack == "account":
                if module.startswith("pam_succeed_if"):
                    match = succ_if_re.match(args)
                    if match is not None and match.group(2) is not None:
                        self.setParam("uidMin", match.group(2), ref)

        # Special handling for pam_pwquality and pam_passwdqc: there can be
        # only one.
        if self.enablePWQuality and self.enablePasswdQC:
            self.setParam("enablePasswdQC", False, ref)
        if not self.enablePWQuality and not self.enablePasswdQC:
            self.setParam("enablePWQuality", True, ref)

        # Special handling for broken_shadow option
        if (self.brokenShadow and not self.enableLDAPAuth and
                not self.enableKerberos and not self.enableWinbindAuth and
                not self.enableSSSDAuth and not self.enableSmartcard):
            self.forceBrokenShadow = True

    def sssdSupported(self):
        if self.enableForceLegacy or not self.sssdConfig:
            return False
        # we just ignore things which have no support on command line
        nssall = ('NIS', 'LDAP', 'Winbind', 'Hesiod', 'IPAv2')
        pamall = ('Kerberos', 'LDAPAuth', 'WinbindAuth', 'Smartcard')
        idsupported = ('LDAP')
        authsupported = ('Kerberos', 'LDAPAuth')
        num = 0
        for t in nssall:
            if getattr(self, 'enable' + t):
                if t not in idsupported:
                    return False
                num += 1
        if num != 1:
            return False
        num = 0
        for t in pamall:
            if getattr(self, 'enable' + t):
                if t not in authsupported:
                    return False
                num += 1
        if num != 1:
            return False
        # realm via DNS is not supported by the current SSSD
        if self.enableKerberos and self.kerberosRealmviaDNS:
            return False
        return True

        # Read hints from the network control file.
    def readNetwork(self, ref):
        # Open the file.  Bail if it's not there.
        try:
            shv = shvfile.read(all_configs[CFG_NETWORK].origPath)
        except IOError:
            return False

        tmp = shv.getValue("NISDOMAIN")
        if tmp:
            self.nisLocalDomain = tmp

        shv.close()

        if self.nisLocalDomain:
            self.setParam("nisDomain", self.nisLocalDomain, ref)

        return True

    def readSSSD(self, ref):
        if not self.sssdConfig:
            return True
        self.sssdConfig = SSSDConfig.SSSDConfig()
        try:
            self.sssdConfig.import_config(all_configs[CFG_SSSD].origPath)
        except (IOError, SSSDConfig.ParsingError):
            self.sssdConfig = SSSDConfig.SSSDConfig()
            self.sssdConfig.new_config()
        try:
            domain = self.sssdDomain = self.sssdConfig.get_domain(SSSD_AUTHCONFIG_DOMAIN)
        except SSSDConfig.NoDomainError:
            try:
                domname = self.sssdConfig.list_active_domains()[0]
            except IndexError:
                try:
                    domname = self.sssdConfig.list_domains()[0]
                except IndexError:
                    return True
            domain = self.sssdConfig.get_domain(domname)
            try:
                idprov = domain.get_option('id_provider')
            except SSSDConfig.NoOptionError:
                idprov = None
            try:
                authprov = domain.get_option('auth_provider')
            except SSSDConfig.NoOptionError:
                authprov = None
        for (attr, opt) in sssd_options:
            try:
                val = domain.get_option(opt)
                if opt == 'ldap_uri':
                    val = " ".join(val.split(","))
                elif opt == 'ldap_schema' and val == 'rfc2307':
                    continue
                elif opt == 'krb5_store_password_if_offline':
                    continue
                self.setParam(attr, val, ref)
            except SSSDConfig.NoOptionError:
                pass

    def validateLDAPURI(self, s):
        """
        Check whether LDAP URI is valid.
        """
        if ',' in s:
            uris = s.split(',')
        else:
            uris = s.split()
        for uri in uris:
            try:
                p = parse.urlparse(uri).port
            except (ValueError, socket.error):
                return False
        return True

    def ldapHostsToURIs(self, s, validate):
        if ',' in s:
            l = s.split(',')
        else:
            l = s.split()
        ret = ""
        for item in l:
            if item:
                if ret:
                    ret += ","
                if "://" in item:
                    ret += item
                else:
                    ret += "ldap://" + item + "/"
        if validate and not self.validateLDAPURI(ret):
            self.messageCB(_("Invalid LDAP URI."))
        return ret

    # Read LDAP setup from /etc/ldap.conf.
    def readLDAP(self, ref):
        # Open the file.  Bail if it's not there or there's some problem
        # reading it.
        try:
            f = open(all_configs[CFG_NSSLDAP].origPath, "r")
        except IOError:
            try:
                f = open(all_configs[CFG_NSLCD].origPath, "r")
            except IOError:
                try:
                    f = open(all_configs[CFG_PAMLDAP].origPath, "r")
                except IOError:
                    try:
                        f = open(all_configs[CFG_OPENLDAP].origPath, "r")
                    except IOError:
                        self.ldapCacertDir = PATH_LDAP_CACERTS
                        return False

        for line in f:
            line = line.strip()

            # Is it a "base" statement?
            value = matchKeyI(line, "base")
            if value and checkDN(value):
                # Save the base DN.
                self.setParam("ldapBaseDN", value, ref)
                continue
            # Is it a "host" statement?
            value = matchKeyI(line, "host")
            if value:
                # Save the host name or IP.
                self.setParam("ldapServer", value, ref)
                continue
            # Is it a "uri" statement?
            value = matchKeyI(line, "uri")
            if value:
                # Save the host name or IP.
                self.setParam("ldapServer", value, ref)
                continue
            # Is it a "ssl" statement?
            value = matchKeyI(line, "ssl")
            if value:
                self.setParam("enableLDAPS", matchLine(value, "start_tls"), ref)
                continue
            # Is it a "nss_schema" statement?
            value = matchKeyI(line, "nss_schema")
            if value:
                self.setParam("ldapSchema", value, ref)
                continue
            value = matchKeyI(line, "tls_cacertdir")
            if value:
                self.setParam("ldapCacertDir", value, ref)
                continue
                # We'll pull MD5/DES crypt ("pam_password") from the config
                # file, or from the pam_unix PAM config lines.

        self.ldapServer = self.ldapHostsToURIs(cleanList(self.ldapServer), False)
        if not self.ldapCacertDir:
            self.ldapCacertDir = PATH_LDAP_CACERTS
        f.close()
        return True

    # Read Kerberos setup from /etc/krb5.conf.
    def getKerberosKDC(self, realm):
        try:
            return self.allKerberosKDCs[realm]
        except KeyError:
            return ""

    def getKerberosAdminServer(self, realm):
        try:
            return self.allKerberosAdminServers[realm]
        except KeyError:
            return ""

    def readKerberos(self, ref):
        section = ""
        self.allKerberosKDCs = {}
        self.allKerberosAdminServers = {}
        # Open the file.  Bail if it's not there or there's some problem
        # reading it.
        try:
            f = open(all_configs[CFG_KRB5].origPath, "r")
        except IOError:
            return False

        for line in f:
            line = line.split('#')[0]
            line = line.strip()

            # If it's a new section, note which one we're "in".
            if line[0:1] == "[":
                section = line[1:-1]
                subsection = ""
                continue

            if section == "libdefaults":
                # Check for the default realm setting.
                value = matchKeyEquals(line, "default_realm")
                if value:
                    self.setParam("kerberosRealm", value, ref)
                    continue
                # Check for the DNS settings.
                value = matchKeyEquals(line, "dns_lookup_kdc")
                if value:
                    self.setParam("kerberosKDCviaDNS", matchKey(value, "true") == "", ref)
                    continue
                value = matchKeyEquals(line, "dns_lookup_realm")
                if value:
                    self.setParam("kerberosRealmviaDNS", matchKey(value, "true") == "", ref)
                    continue

            elif section == "realms":
                if not subsection:
                    # Read the name of the realm.
                    value = line.split(None, 1)
                    if len(value) < 1:
                        continue
                    subsection = value[0]
                # Check for the end of a realm section.
                else:
                    if line[0:1] == "}":
                        subsection = ""
                        continue
                    if not self.kerberosRealm:
                        # No reason to use setParam here
                        self.kerberosRealm = subsection
                    # See if this is a key we care about.
                    value = matchKeyEquals(line, "kdc")
                    if value:
                        self.allKerberosKDCs[subsection] = commaAppend(self.getKerberosKDC(subsection), value)
                        continue
                    value = matchKeyEquals(line, "admin_server")
                    if value:
                        self.allKerberosAdminServers[subsection] = commaAppend(self.getKerberosAdminServer(subsection),
                                                                               value)
        if self.kerberosRealm:
            self.setParam("kerberosKDC", self.getKerberosKDC(self.kerberosRealm), ref)
            self.setParam("kerberosAdminServer", self.getKerberosAdminServer(self.kerberosRealm), ref)
        f.close()
        return True

    def testLDAPCACerts(self):
        if self.enableLDAP or self.enableLDAPAuth or self.ldapCacertURL:
            try:
                os.stat(self.ldapCacertDir)
            except OSError as err:
                if err.errno == errno.ENOENT:
                    os.mkdir(self.ldapCacertDir, 0o755)

            return isEmptyDir(self.ldapCacertDir)
        return False

    def rehashLDAPCACerts(self):
        if ((self.enableLDAP or self.enableLDAPAuth) and
                (self.enableLDAPS or 'ldaps:' in self.ldapServer)) or self.ldapCacertURL:
            os.system("/usr/sbin/cacertdir_rehash " + self.ldapCacertDir)


    def downloadLDAPCACert(self):
        if not self.ldapCacertURL:
            return False
        self.testLDAPCACerts()
        try:
            readf = request.urlopen(self.ldapCacertURL)
            writef = openLocked(self.ldapCacertDir + "/" + LDAP_CACERT_DOWNLOADED, 0o644)
            writef.write(readf.read().decode())
            readf.close()
            writef.close()
        except (IOError, OSError, ValueError):
            self.messageCB(_("Error downloading CA certificate"))
            return False
        self.rehashLDAPCACerts()
        return True

    def checkPAMLinked(self):
        for dest in [AUTH_PAM_SERVICE, POSTLOGIN_PAM_SERVICE, PASSWORD_AUTH_PAM_SERVICE,
                     FINGERPRINT_AUTH_PAM_SERVICE, SMARTCARD_AUTH_PAM_SERVICE]:
            dest = SYSCONFDIR + "/pam.d/" + dest
            f = os.path.isfile(dest)
            l = os.path.islink(dest)
            if (f and not l) or (l and not f):
                self.pamLinked = False
                return

    def writeChanged(self, ref):
        self.checkPAMLinked()
        self.update(True)
        self.prewriteUpdate()
        self.setupBackup(PATH_CONFIG_BACKUPS + "/last")
        ret = True
        try:
            for group in self.save_groups:
                if group.attrsDiffer(self, ref):
                    if group.saveFunction:
                        ret = ret and group.saveFunction()
                    if group.toggleFunction:
                        self.toggleFunctions.add(group.toggleFunction)
        except (OSError, IOError):
            sys.stderr.write(str(sys.exc_info()[1]) + "\n")
            return False
        return ret

    def prewriteUpdate(self):
        oldimplicit = self.implicitSSSD
        self.implicitSSSD = self.implicitSSSDAuth = self.sssdSupported()
        if not self.enableSSSD and not self.enableSSSDAuth:
            if self.implicitSSSD and not oldimplicit:
                self.inconsistentAttrs.append('forceSSSDUpdate')
        modules = getSmartcardModules()
        if len(modules) > 0 and self.smartcardModule not in modules:
            self.smartcardModule = modules[0]
        if self.ipaDomainJoined and not self.enableIPAv2:
            # must uninstall IPAv2
            self.ipaDomainJoined = False
            self.ipaUninstall = True

    def setupBackup(self, backupdir):
        if not os.path.isdir(PATH_CONFIG_BACKUPS):
            os.mkdir(PATH_CONFIG_BACKUPS)
        if backupdir[0] != "/":
            backupdir = PATH_CONFIG_BACKUPS + "/backup-" + backupdir
        self.backupDir = backupdir
        if not isEmptyDir(backupdir):
            try:
                lst = os.listdir(backupdir)
                for filename in lst:
                    try:
                        os.unlink(backupdir + "/" + filename)
                    except OSError:
                        pass
            except OSError:
                pass

    def saveBackup(self, backupdir):
        self.setupBackup(backupdir)
        ret = True
        for cfg in all_configs:
            ret = cfg.backup(self.backupDir) and ret
        return ret

    def restoreBackup(self, backupdir):
        if backupdir[0] != "/":
            backupdir = PATH_CONFIG_BACKUPS + "/backup-" + backupdir
        ret = True
        for cfg in all_configs:
            ret = cfg.restore(backupdir) and ret
        return ret

    def restoreLast(self):
        return self.restoreBackup(PATH_CONFIG_BACKUPS + "/last")

    def writeCache(self):
        all_configs[CFG_CACHE].backup(self.backupDir)
        writeCache(self.enableCache and not self.implicitSSSD)
        return True

    def toggleCachingService(self, nostart):
        if not nostart:
            if self.enableCache:
                Service.stop("nscd")
                Service.start("nscd")
            else:
                try:
                    Service.stop("nscd")
                except OSError:
                    pass
        return True

    # Write LDAP setup to an ldap.conf using host and base as keys.
    def writeLDAP2(self, filename, uri, host, base, writepadl, writeschema, writepam):
        wrotebasedn = False
        wroteserver = False
        wrotessl = False
        wroteschema = False
        wrotepass = False
        wrotecacertdir = False
        f = None
        output = ""
        if (self.passwordAlgorithm and self.passwordAlgorithm != "descrypt" and
                    self.passwordAlgorithm != "bigcrypt"):
            passalgo = "md5"
        else:
            passalgo = "crypt"
        try:
            f = SafeFile(filename, 0o644)

            # Read in the old file.
            for line in f.file:
                line = line.decode('utf-8')
                ls = line.strip()
                # If it's a 'uri' line, insert ours instead.
                if matchLine(ls, uri):
                    if not wroteserver and self.ldapServer:
                        output += uri + " "
                        output += " ".join(self.ldapServer.split(","))
                        output += "\n"
                        wroteserver = True
                # If it's a 'host' line, comment it out.
                elif matchLine(ls, host):
                    if self.ldapServer:
                        output += "#" + line
                elif matchBaseLine(ls, base):
                    # If it's a 'base' line, insert ours instead.
                    if not wrotebasedn and self.ldapBaseDN:
                        output += base + " "
                        output += self.ldapBaseDN
                        output += "\n"
                        wrotebasedn = True
                elif writepadl and matchLine(ls, "ssl"):
                    # If it's an 'ssl' line, insert ours instead.
                    if not wrotessl:
                        output += "ssl "
                        if self.enableLDAPS:
                            output += "start_tls"
                        else:
                            output += "no"
                        output += "\n"
                        wrotessl = True
                elif writeschema and matchLine(ls, "nss_schema"):
                    # If it's an 'nss_schema' line, insert ours instead.
                    if not wroteschema and self.ldapSchema:
                        output += "nss_schema "
                        output += self.ldapSchema
                        output += "\n"
                        wroteschema = True
                elif matchLineI(ls, "tls_cacertdir"):
                    # If it's an 'tls_cacertdir' line, insert ours instead.
                    if not wrotecacertdir:
                        if writepadl:
                            output += "tls_cacertdir"
                        else:
                            output += "TLS_CACERTDIR"
                        output += " " + self.ldapCacertDir
                        output += "\n"
                        wrotecacertdir = True
                elif writepam and matchLine(ls, "pam_password"):
                    # If it's a 'pam_password' line, write the correct setting.
                    if not wrotepass:
                        output += "pam_password " + passalgo
                        output += "\n"
                        wrotepass = True
                else:
                    # Otherwise, just copy the current line out.
                    output += line

            # If we haven't encountered either of the config lines yet...
            if not wroteserver and self.ldapServer:
                output += uri + " "
                output += " ".join(self.ldapServer.split(","))
                output += "\n"
            if not wrotebasedn and self.ldapBaseDN:
                output += base + " "
                output += self.ldapBaseDN
                output += "\n"
            if writepadl and not wrotessl:
                output += "ssl "
                if self.enableLDAPS:
                    output += "start_tls"
                else:
                    output += "no"
                output += "\n"
            if writeschema and not wroteschema and self.ldapSchema:
                output += "nss_schema "
                output += self.ldapSchema
                output += "\n"
            if not wrotecacertdir:
                if writepadl:
                    output += "tls_cacertdir"
                else:
                    output += "TLS_CACERTDIR"
                output += " " + self.ldapCacertDir
                output += "\n"
            if writepam and not wrotepass:
                output += "pam_password " + passalgo
                output += "\n"
            # Write it out and close it.
            f.rewind()
            f.write(output.encode('utf-8'))
            f.save()
        finally:
            try:
                if f:
                    f.close()
            except IOError:
                pass
        return True

    def writeLDAP(self):
        if os.path.isfile(all_configs[CFG_NSSLDAP].origPath):
            all_configs[CFG_NSSLDAP].backup(self.backupDir)
            self.writeLDAP2(all_configs[CFG_NSSLDAP].origPath,
                            "uri", "host", "base", True, True, False)
        if os.path.isfile(all_configs[CFG_PAMLDAP].origPath):
            all_configs[CFG_PAMLDAP].backup(self.backupDir)
            self.writeLDAP2(all_configs[CFG_PAMLDAP].origPath,
                            "uri", "host", "base", True, False, True)
        if os.path.isfile(all_configs[CFG_NSLCD].origPath):
            all_configs[CFG_NSLCD].backup(self.backupDir)
            self.writeLDAP2(all_configs[CFG_NSLCD].origPath,
                            "uri", "host", "base", True, False, False)
        all_configs[CFG_OPENLDAP].backup(self.backupDir)
        ret = self.writeLDAP2(all_configs[CFG_OPENLDAP].origPath,
                              "URI", "HOST", "BASE", False, False, False)
        return ret


    # Write Kerberos 5 setup to /etc/krb5.conf.
    def writeKerberos(self):
        wroterealm = False
        wrotekdc = False
        wroteadmin = False
        wrotesmbrealm = False
        wrotesmbkdc = False
        wroterealms = False
        wrotelibdefaults = False
        wroterealms2 = False
        wrotelibdefaults2 = False
        wrotedefaultrealm = False
        wrotednsrealm = False
        wrotednskdc = False
        wroteourdomrealm = False
        wrotedomrealm = False
        wrotedomrealm2 = False
        section = ""
        subsection = ""
        f = None
        output = ""
        all_configs[CFG_KRB5].backup(self.backupDir)
        if self.enableKerberos and self.kerberosRealm:
            defaultrealm = self.kerberosRealm
        elif (self.enableWinbind or
                  self.enableWinbindAuth) and self.smbSecurity == "ads" and self.smbRealm:
            defaultrealm = self.smbRealm
        else:
            defaultrealm = self.kerberosRealm
        if self.kerberosRealm == self.smbRealm:
            wrotesmbrealm = True
        try:
            f = SafeFile(all_configs[CFG_KRB5].origPath, 0o644)

            # Read in the old file.
            for line in f.file:
                line = line.decode('utf-8')
                ls = line.strip()

                # If this is the "kdc" in our realm, replace it with
                # the values we now have.
                if (section == "realms" and subsection and subsection == self.kerberosRealm
                    and matchLine(ls, "kdc")):
                    if not wrotekdc:
                        if self.kerberosKDC:
                            output += krbKdc(self.kerberosKDC)
                        wrotekdc = True
                    continue
                # If this is the "kdc" in the SMB realm, replace it with
                # the values we now have.
                if (section == "realms" and self.smbSecurity == "ads" and subsection
                    and subsection == self.smbRealm and matchLine(ls, "kdc")):
                    if not wrotesmbkdc:
                        if self.smbServers:
                            output += krbKdc(self.smbServers)
                        wrotesmbkdc = True
                    continue
                # If this is the "admin_server" in our realm, replace it with
                # the values we now have.
                if (section == "realms" and subsection and subsection == self.kerberosRealm
                    and matchLine(ls, "admin_server")):
                    if not wroteadmin:
                        if self.kerberosAdminServer:
                            output += krbAdminServer(self.kerberosAdminServer)
                        wroteadmin = True
                    continue
                # If we're in the realms section, but not in a realm, we'd
                # better be looking at the beginning of one.
                if section == "realms" and not subsection:
                    # Read the name of the realm.
                    value = ls.split(None, 1)
                    if len(value) < 1:
                        output += line
                        continue
                    subsection = value[0]
                    # If this is the section for our realm, mark
                    # that.
                    if self.kerberosRealm and subsection == self.kerberosRealm:
                        wroterealm = True
                    if self.smbRealm and subsection == self.smbRealm:
                        wrotesmbrealm = True
                # If it's the end of a subsection, mark that.
                if section == "realms" and subsection and matchLine(ls, "}"):
                    # If it's the right section of realms, write out
                    # info we haven't already written.
                    if self.kerberosRealm and subsection == self.kerberosRealm:
                        if not wrotekdc:
                            output += krbKdc(self.kerberosKDC)
                            wrotekdc = True
                        if not wroteadmin:
                            output += krbAdminServer(self.kerberosAdminServer)
                            wroteadmin = True
                    if self.smbRealm and subsection == self.smbRealm:
                        if not wrotesmbkdc:
                            output += krbKdc(self.smbServers)
                            wrotesmbkdc = True
                    subsection = ""
                # If we're in the libdefaults section, and this is the
                # default_realm keyword, replace it with ours.
                if section == "libdefaults" and matchLine(ls, "default_realm"):
                    if defaultrealm and not wrotedefaultrealm:
                        output += " default_realm = "
                        output += defaultrealm
                        output += "\n"
                        wrotedefaultrealm = True
                    continue
                if section == "libdefaults" and matchLine(ls, "dns_lookup_realm"):
                    if not wrotednsrealm:
                        output += " dns_lookup_realm = "
                        output += str(bool(self.kerberosRealmviaDNS)).lower()
                        output += "\n"
                        wrotednsrealm = True
                    continue
                if section == "libdefaults" and matchLine(ls, "dns_lookup_kdc"):
                    if not wrotednskdc:
                        output += " dns_lookup_kdc = "
                        output += str(bool(self.kerberosKDCviaDNS)).lower()
                        output += "\n"
                        wrotednskdc = True
                    continue
                # don't change the domain_realm mapping if it's already there
                if section == "domain_realm" and self.kerberosRealm and (matchLine(ls, self.kerberosRealm.lower())
                                                                         or matchLine(ls,
                                                                                      "." + self.kerberosRealm.lower())):
                    output += line
                    wroteourdomrealm = True
                    continue
                # If it's the beginning of a section, record its name.
                if matchLine(ls, "["):
                    # If the previous section was "realms", and we didn't
                    # see ours, write our realm out.
                    if (section == "realms" and self.kerberosRealm
                        and not wroterealm):
                        output += krbRealm(self.kerberosRealm,
                                           self.kerberosKDC,
                                           self.kerberosAdminServer)
                        wroterealm = True
                    # If the previous section was "realms", and we didn't
                    # see the SMB realm, write it out.
                    if (section == "realms" and self.smbRealm
                        and not wrotesmbrealm):
                        output += krbRealm(self.smbRealm,
                                           self.smbServers, "")
                        wrotesmbrealm = True
                    # If the previous section was "libdefaults", and we
                    # didn't see a "default_realm", write it out.
                    if section == "libdefaults":
                        if defaultrealm and not wrotedefaultrealm:
                            output += " default_realm = "
                            output += defaultrealm
                            output += "\n"
                            wrotedefaultrealm = True
                        if self.kerberosRealmviaDNS is not None and not wrotednsrealm:
                            output += " dns_lookup_realm = "
                            output += str(bool(self.kerberosRealmviaDNS)).lower()
                            output += "\n"
                            wrotednsrealm = True
                        if self.kerberosKDCviaDNS is not None and not wrotednskdc:
                            output += " dns_lookup_kdc = "
                            output += str(bool(self.kerberosKDCviaDNS)).lower()
                            output += "\n"
                            wrotednskdc = True
                    if section == "domain_realm":
                        if self.kerberosRealm and not wroteourdomrealm:
                            output += " " + self.kerberosRealm.lower()
                            output += " = " + self.kerberosRealm
                            output += "\n"
                            output += " ." + self.kerberosRealm.lower()
                            output += " = " + self.kerberosRealm
                            output += "\n"
                            wroteourdomrealm = True
                    if section:
                        if section == "realms":
                            wroterealms2 = True
                        elif section == "libdefaults":
                            wrotelibdefaults2 = True
                        elif section == "domain_realm":
                            wrotedomrealm2 = True
                    section = ls[1:].split("]", 1)[0]
                    if section == "realms":
                        wroterealms = True
                    elif section == "libdefaults":
                        wrotelibdefaults = True
                    elif section == "domain_realm":
                        wrotedomrealm = True

                # Otherwise, just copy the current line out.
                output += line

            # If we haven't encountered a libdefaults section yet...
            if not wrotelibdefaults2:
                if not wrotelibdefaults:
                    output += "[libdefaults]\n"
                if defaultrealm and not wrotedefaultrealm:
                    output += " default_realm = "
                    output += defaultrealm
                    output += "\n"
                if self.kerberosRealmviaDNS is not None and not wrotednsrealm:
                    output += " dns_lookup_realm = "
                    output += str(bool(self.kerberosRealmviaDNS)).lower()
                    output += "\n"
                if self.kerberosKDCviaDNS is not None and not wrotednskdc:
                    output += " dns_lookup_kdc = "
                    output += str(bool(self.kerberosKDCviaDNS)).lower()
                    output += "\n"
            # If we haven't encountered a realms section yet...
            if not wroterealms2 and (self.kerberosRealm or self.smbRealm):
                if not wroterealms:
                    output += "[realms]\n"
                if not wroterealm:
                    output += krbRealm(self.kerberosRealm, self.kerberosKDC,
                                       self.kerberosAdminServer)
                if not wrotesmbrealm:
                    output += krbRealm(self.smbRealm, self.smbServers, "")
            if not wrotedomrealm2 and self.kerberosRealm:
                if not wrotedomrealm:
                    output += "[domain_realm]\n"
                if self.kerberosRealm and not wroteourdomrealm:
                    output += " " + self.kerberosRealm.lower()
                    output += " = " + self.kerberosRealm
                    output += "\n"
                    output += " ." + self.kerberosRealm.lower()
                    output += " = " + self.kerberosRealm
                    output += "\n"

            # Write it out and close it.
            f.rewind()
            f.write(output.encode('utf-8'))
            f.save()
        finally:
            try:
                if f:
                    f.close()
            except IOError:
                pass
        return True

    def changeProvider(self, domain, newprovider, subtype):
        try:
            prov = domain.get_option(subtype + '_provider')
        except SSSDConfig.NoOptionError:
            prov = None
        if prov != newprovider:
            if prov is not None:
                domain.remove_provider(subtype)
            domain.add_provider(newprovider, subtype)

    def writeSSSD(self):
        if not self.sssdConfig:
            return True

        all_configs[CFG_SSSD].backup(self.backupDir)

        if self.enableIPAv2:
            # just save the backup
            return True

        if not self.sssdDomain:
            if not self.implicitSSSD:
                # do not create a domain that would be incomplete anyway
                return True
            try:
                self.sssdDomain = self.sssdConfig.new_domain(SSSD_AUTHCONFIG_DOMAIN)
            except SSSDConfig.DomainAlreadyExistsError:
                self.sssdDomain = self.sssdConfig.get_domain(SSSD_AUTHCONFIG_DOMAIN)
        domain = self.sssdDomain

        try:
            self.sssdConfig.get_service('autofs')
        except SSSDConfig.NoServiceError:
            self.sssdConfig.new_service('autofs')
        self.sssdConfig.activate_service('autofs')

        activate = False
        if self.enableLDAP:
            activate = True
            self.changeProvider(domain, 'ldap', 'id')
            self.changeProvider(domain, 'ldap', 'autofs')
        if self.enableKerberos:
            self.changeProvider(domain, 'krb5', 'auth')
            self.changeProvider(domain, 'krb5', 'chpass')
        elif self.enableLDAPAuth:
            self.changeProvider(domain, 'ldap', 'auth')
            self.changeProvider(domain, 'ldap', 'chpass')

        for (attr, option) in sssd_options:
            try:
                val = getattr(self, attr)
                if option == 'ldap_uri':
                    val = cleanList(val)
                if type(val) == bool:
                    domain.set_option(option, val)
                elif type(val) == str:
                    if val:
                        domain.set_option(option, val)
                    else:
                        domain.remove_option(option)
                else:
                    domain.remove_option(option)
            except SSSDConfig.NoOptionError:
                pass
        self.sssdConfig.save_domain(domain)

        if activate:
            self.sssdConfig.activate_domain(domain.get_name())
        else:
            self.sssdConfig.deactivate_domain(domain.get_name())

        try:
            self.sssdConfig.write(all_configs[CFG_SSSD].origPath)
        except IOError:
            pass
        return True


    def toggleSSSDService(self, nostart):
        explicitenable = ((self.enableSSSD and self.enableSSSDAuth) or
                          (self.enableSSSD and os.path.exists(PATH_SSSD_CONFIG)) or
                          (self.enableSSSDAuth and os.path.exists(PATH_SSSD_CONFIG)))
        enable = (self.implicitSSSD or self.implicitSSSDAuth or
                  self.enableIPAv2 or explicitenable)
        toggleSplatbindService(enable,
                               PATH_SSSD,
                               "sssd", nostart or (enable and not (self.implicitSSSD or
                                                                   self.implicitSSSDAuth or self.enableIPAv2)))


    # Write NSS setup to /etc/nsswitch.conf.
    def writeNSS(self):
        users = ""
        normal = ""
        hosts = ""
        wrotepasswd = False
        wrotegroup = False
        wroteshadow = False
        wrotenetgroup = False
        wroteautomount = False
        wrotehosts = False
        wroteinitgroups = False
        wroteservices = False
        f = None
        output = ""
        all_configs[CFG_NSSWITCH].backup(self.backupDir)
        try:
            f = SafeFile(all_configs[CFG_NSSWITCH].origPath, 0o644)

            # Determine what we want in that file for most of the databases. If
            # we're using DB, we're doing it for speed, so put it in first.  Then
            # comes files.  Then everything else in reverse alphabetic order.
            if self.enableDB:
                normal += " db"
            normal += " files"
            if self.enableAltfiles:
                normal += " altfiles"
            services = normal
            if self.enableDirectories:
                normal += " directories"
            if self.enableOdbcbind:
                normal += " odbcbind"
            if self.enableNIS3:
                normal += " nisplus"
            if self.enableNIS:
                normal += " nis"
            if self.enableSSSD or self.implicitSSSD or self.enableIPAv2:
                normal += " sss"
                services += " sss"
            if self.enableLDAPbind:
                normal += " ldapbind"
            if self.enableLDAP and not self.implicitSSSD:
                normal += " ldap"
            if self.enableHesiodbind:
                normal += " hesiodbind"
            if self.enableHesiod:
                normal += " hesiod"
            if self.enableDBIbind:
                normal += " dbibind"
            if self.enableDBbind:
                normal += " dbbind"

            netgroup = normal

            # Generate the list for users and groups.  The same as most other
            # services, just use "compat" instead of "files" if "compat" is
            # enabled.
            if self.enableCompat:
                users = normal.replace("files", "compat")
            else:
                users = normal

            if self.enableWinbind:
                users += " winbind"

            if not os.access(PATH_LIBSSS_AUTOFS, os.R_OK):
                # No support for automount in sssd
                if self.enableLDAP and self.implicitSSSD:
                    normal = normal.replace("sss", "ldap")
                else:
                    normal = normal.replace(" sss", "")

            # Hostnames we treat specially.
            hosts += " files"
            if self.enableMDNS:
                hosts += " mdns4_minimal [NOTFOUND=return]"
            if self.preferDNSinHosts:
                hosts += " dns"
            if self.enableWINS:
                hosts += " wins"
            if self.enableNIS3:
                hosts += " nisplus"
            if self.enableNIS:
                hosts += " nis"
            if not self.preferDNSinHosts:
                hosts += " dns"
            if self.enableMyhostname:
                hosts += " myhostname"

            # Read in the old file.
            for line in f.file:
                line = line.decode('utf-8')
                ls = line.strip()

                # If it's a 'passwd' line, insert ours instead.
                if matchLine(ls, "passwd:"):
                    if not wrotepasswd:
                        output += "passwd:    "
                        output += users
                        output += "\n"
                        wrotepasswd = True

                # If it's a 'shadow' line, insert ours instead.
                elif matchLine(ls, "shadow:"):
                    if not wroteshadow:
                        output += "shadow:    "
                        output += users
                        output += "\n"
                        wroteshadow = True
                # If it's a 'group' line, insert ours instead.
                elif matchLine(ls, "group:"):
                    if not wrotegroup:
                        output += "group:     "
                        output += users
                        output += "\n"
                        wrotegroup = True
                # If it's a 'initgroups' line, comment it out instead.
                elif matchLine(ls, "initgroups:"):
                    if not wroteinitgroups:
                        output += "#"
                        output += line
                        wroteinitgroups = True
                # If it's a 'netgroup' line, insert ours instead.
                elif matchLine(ls, "netgroup:"):
                    if not wrotenetgroup:
                        output += "netgroup:  "
                        output += netgroup
                        output += "\n"
                        wrotenetgroup = True
                # If it's a 'automount' line, insert ours instead.
                elif matchLine(ls, "automount:"):
                    if not wroteautomount:
                        output += "automount: "
                        output += normal
                        output += "\n"
                        wroteautomount = True
                # If it's a 'hosts' line, insert ours instead.
                elif matchLine(ls, "hosts:"):
                    if not wrotehosts:
                        output += "hosts:     "
                        output += hosts
                        output += "\n"
                        wrotehosts = True
                # If it's a 'services' line, insert ours instead.
                elif matchLine(ls, "services:"):
                    if not wroteservices:
                        output += "services:  "
                        output += services
                        output += "\n"
                        wroteservices = True
                # Otherwise, just copy the current line out.
                else:
                    output += line

            # If we haven't encountered any of the config lines yet...
            if not wrotepasswd:
                output += "passwd:    "
                output += users
                output += "\n"
            if not wroteshadow:
                output += "shadow:    "
                output += users
                output += "\n"
            if not wrotegroup:
                output += "group:     "
                output += users
                output += "\n"
            if not wrotenetgroup:
                output += "netgroup:  "
                output += netgroup
                output += "\n"
            if not wroteautomount:
                output += "automount: "
                output += normal
                output += "\n"
            if not wrotehosts:
                output += "hosts:     "
                output += hosts
                output += "\n"
            if not wroteservices:
                output += "services:  "
                output += services
                output += "\n"
            # For now we do not write initgroups
            # line if not encountered.

            # Write it out and close it.
            f.rewind()
            f.write(output.encode('utf-8'))
            f.save()
        finally:
            try:
                if f:
                    f.close()
            except IOError:
                pass
        return True

    def linkPAMService(self, src, dest):
        f = os.path.isfile(dest)
        l = os.path.islink(dest)
        if (f and not l) or (l and not f):
            # Create the link only if it doesn't exist yet or is invalid
            try:
                os.unlink(dest)
            except OSError:
                pass
            try:
                os.symlink(src, dest)
            except OSError:
                pass

    def formatPAMModule(self, module, forcescard, warn):
        stack = pam_stacks[module[STACK]]
        logic = module[LOGIC]
        name = module[NAME]
        output = ""
        if stack and logic:
            args = ""
            if name == "pkcs11" and stack == "auth":
                if forcescard:
                    if self.enableKerberos:
                        logic = LOGIC_FORCE_PKCS11_KRB5
                    else:
                        logic = LOGIC_FORCE_PKCS11
                    args = " ".join(argv_force_pkcs11_auth)
                else:
                    if self.enableKerberos:
                        logic = LOGIC_PKCS11_KRB5
            if name == "krb5" and stack == "account":
                if self.enableSmartcard:
                    logic = LOGIC_IGNORE_AUTH_ERR
                else:
                    logic = LOGIC_IGNORE_UNKNOWN
            if name == "succeed_if":
                if stack == "auth" and logic == LOGIC_SKIPNEXT:
                    if self.enableKerberos:
                        logic = LOGIC_SKIPNEXT3
                elif stack == "auth" or stack == "account":
                    if self.uidMin is not None:
                        argv = module[ARGV][0:]  # shallow copy
                        argv[1] = self.uidMin
                        args = " ".join(argv)
            # do not continue to following modules if authentication fails
            if name == "unix" and stack == "auth" and (self.enableSSSDAuth or
                                                           self.implicitSSSDAuth or self.enableIPAv2) and (
                    not self.enableNIS):
                logic = LOGIC_FORCE_PKCS11  # make it or break it logic
            # use oddjob_mkhomedir if available
            if name == "mkhomedir" and os.access("%s/pam_%s.so"
                                                         % (AUTH_MODULE_DIR, "oddjob_mkhomedir"), os.X_OK):
                name = "oddjob_mkhomedir"
            # the missing pam_systemd module should not be logged as error
            if name == "systemd":
                output += "-"
                warn = False
            output += "%-12s%-13s pam_%s.so" % (stack, logic,
                                                name)
            if warn and not name in self.module_missing and not os.access("%s/pam_%s.so"
                                                                                  % (AUTH_MODULE_DIR, name),
                                                                          os.X_OK):
                self.messageCB(_(
                    "Authentication module %s/pam_%s.so is missing. Authentication process might not work correctly." %
                    (AUTH_MODULE_DIR, name)))
                self.module_missing[name] = True
            if name == "pwquality":
                args = self.pwqualityArgs
            if name == "passwdqc":
                args = self.passwdqcArgs
            if name == "localuser":
                args = self.localuserArgs
            if name == "access":
                args = self.pamAccessArgs
            if name == "mkhomedir" or name == "oddjob_mkhomedir":
                args = self.mkhomedirArgs
            if name == "systemd":
                args = self.systemdArgs
            if name == "sss" and stack == "auth" and not self.enableNIS:
                args = "forward_pass"
            if not args and module[ARGV]:
                args = " ".join(module[ARGV])
            if name == "winbind" and self.winbindOffline and stack != "password":
                output += " cached_login"
            if name == "winbind" and self.winbindKrb5:
                output += " krb5_auth krb5_ccache_type=KEYRING"
            if name == "unix":
                if stack == "password":
                    if self.passwordAlgorithm and self.passwordAlgorithm != "descrypt":
                        output += " " + self.passwordAlgorithm
                    if self.algoRounds:
                        output += " rounds=" + self.algoRounds
                    if self.enableShadow:
                        output += " shadow"
                    if self.enableNIS:
                        output += " nis"
                    if self.enableNullOk:
                        output += " nullok"
                if stack == "auth":
                    if self.enableNullOk:
                        output += " nullok"
                if stack == "account":
                    if (self.forceBrokenShadow or self.enableLDAPAuth or
                            self.enableKerberos or self.enableWinbindAuth):
                        output += " broken_shadow"
            if args:
                output += " " + args
        output += "\n"
        return output

    def writePAMService(self, service, cfg, cfg_basename, cfg_link):
        f = None
        output = ""
        all_configs[cfg].backup(self.backupDir)
        try:
            f = SafeFile(all_configs[cfg].origPath, 0o644)

            output += "#%PAM-1.0\n"
            output += "# This file is auto-generated.\n"
            output += "# User changes will be destroyed the next time "
            output += "authconfig is run.\n"

            forceSmartcard = self.forceSmartcard
            enableSmartcard = self.enableSmartcard
            enableFprintd = self.enableFprintd
            warn = False
            if service == STANDARD:
                warn = True
            if service == FINGERPRINT:
                enableFprintd = True
            elif service == SMARTCARD:
                enableSmartcard = True
                forceSmartcard = True

            prevmodule = []
            for module in pam_modules[service]:
                if prevmodule and module[STACK] != prevmodule[STACK]:
                    output += "\n"
                prevmodule = module
                if (module[MANDATORY] or
                        (self.enableAFS and module[NAME] == "afs") or
                        (self.enableAFSKerberos and module[NAME] == "afs.krb") or
                        (self.enablePWQuality and module[NAME] == "pwquality") or
                        (self.enableEcryptfs and module[NAME] == "ecryptfs") or
                        (self.enableEPS and module[NAME] == "eps") or
                        ((self.enableKerberos and not self.implicitSSSDAuth) and module[NAME] == "krb5" and
                             not module[ARGV] == argv_krb5_sc_auth) or
                        (self.enableKerberos and enableSmartcard and
                             ((module[NAME] == "krb5" and module[ARGV] == argv_krb5_sc_auth) or
                                  (module[NAME] == "permit" and module[STACK] == AUTH))) or
                        ((self.enableLDAPAuth and not self.implicitSSSDAuth) and module[NAME] == "ldap") or
                        (enableSmartcard and module[STACK] == AUTH and
                                 module[NAME] == "succeed_if" and module[LOGIC] == LOGIC_SKIPNEXT) or
                        (enableSmartcard and module[NAME] == "pkcs11") or
                        (enableSmartcard and forceSmartcard and module[NAME] == "deny") or
                        (enableFprintd and module[NAME] == "fprintd") or
                        (self.enableOTP and module[NAME] == "otp") or
                        (self.enablePasswdQC and module[NAME] == "passwdqc") or
                        (self.enableWinbindAuth and module[NAME] == "winbind") or
                        ((self.enableSSSDAuth or self.implicitSSSDAuth or self.enableIPAv2) and module[
                            NAME] == "sss") or
                        ((self.enableSSSDAuth or self.implicitSSSDAuth or self.enableIPAv2) and
                             (not self.enableNIS) and module[NAME] == "localuser" and module[STACK] == AUTH) or
                        (self.enableLocAuthorize and module[NAME] == "localuser" and module[STACK] == ACCOUNT) or
                        (self.enablePAMAccess and module[NAME] == "access") or
                        (self.enableMkHomeDir and module[NAME] == "mkhomedir") or
                        (not self.enableSysNetAuth and module[STACK] == AUTH and
                                 module[NAME] == "succeed_if" and module[LOGIC] == LOGIC_REQUISITE)):
                    output += self.formatPAMModule(module, forceSmartcard, warn)

            # Write it out and close it.
            f.rewind()
            f.write(output.encode('utf-8'))
            f.save()
        finally:
            try:
                if f:
                    f.close()
            except IOError:
                pass

        self.linkPAMService(cfg_basename, SYSCONFDIR + "/pam.d/" + cfg_link)

        return True

    # Write PAM setup to the control file(s).
    def writePAM(self):
        self.module_missing = {}
        self.writePAMService(STANDARD, CFG_PAM, AUTH_PAM_SERVICE_AC, AUTH_PAM_SERVICE)
        self.writePAMService(POSTLOGIN, CFG_POSTLOGIN_PAM, POSTLOGIN_PAM_SERVICE_AC, POSTLOGIN_PAM_SERVICE)
        self.writePAMService(PASSWORD_ONLY, CFG_PASSWORD_PAM, PASSWORD_AUTH_PAM_SERVICE_AC, PASSWORD_AUTH_PAM_SERVICE)
        self.writePAMService(FINGERPRINT, CFG_FINGERPRINT_PAM, FINGERPRINT_AUTH_PAM_SERVICE_AC,
                             FINGERPRINT_AUTH_PAM_SERVICE)
        self.writePAMService(SMARTCARD, CFG_SMARTCARD_PAM, SMARTCARD_AUTH_PAM_SERVICE_AC, SMARTCARD_AUTH_PAM_SERVICE)
        return True

    def writeNetwork(self):
        all_configs[CFG_NETWORK].backup(self.backupDir)
        try:
            shv = shvfile.rcreate(all_configs[CFG_NETWORK].origPath)
        except IOError:
            return False

        shv.setValue("NISDOMAIN", self.nisDomain)

        shv.write(0o644)
        shv.close()

        return True

    def toggleNisService(self, nostart):
        if self.enableNIS and self.nisDomain:
            if not nostart:
                os.system("/bin/domainname " + self.nisDomain)
            try:
                os.system("[[ $(getsebool allow_ypbind) == *off* ]] && setsebool -P allow_ypbind 1")
                os.stat(PATH_RPCBIND)
                Service.enable("rpcbind")
                if not nostart:
                    Service.start("rpcbind")
            except OSError:
                pass
            try:
                os.stat(PATH_YPBIND)
                Service.enable("ypbind")
                if not nostart:
                    Service.stop("ypbind")
                    Service.start("ypbind")
            except OSError:
                pass
        else:
            if not nostart:
                os.system("/bin/domainname \"(none)\"")
            try:
                os.system("[[ $(getsebool allow_ypbind) == *on* ]] && setsebool -P allow_ypbind 0")
                os.stat(PATH_YPBIND)
                if not nostart:
                    try:
                        Service.stop("ypbind")
                    except OSError:
                        pass
                Service.disable("ypbind")
            except OSError:
                pass
        return True

    def toggleOddjobService(self, nostart):
        if self.enableMkHomeDir and os.access("%s/pam_%s.so"
                                                      % (AUTH_MODULE_DIR, "oddjob_mkhomedir"), os.X_OK):
            # only switch on and only if pam_oddjob_mkhomedir exists
            toggleSplatbindService(True,
                                   PATH_ODDJOBD,
                                   "oddjobd", nostart)

    def toggleLDAPService(self, nostart):
        toggleSplatbindService((self.enableLDAP or self.enableLDAPAuth) and
                               not self.implicitSSSD,
                               PATH_NSLCD,
                               "nslcd", nostart)
        if self.enableLDAP:
            try:
                os.system(
                    "[[ $(getsebool authlogin_nsswitch_use_ldap) == *off* ]] && setsebool -P authlogin_nsswitch_use_ldap 1")
            except OSError:
                pass
        else:
            try:
                os.system(
                    "[[ $(getsebool authlogin_nsswitch_use_ldap) == *on* ]] && setsebool -P authlogin_nsswitch_use_ldap 0")
            except OSError:
                pass
        return True


def writeCache(enabled):
    if enabled:
        Service.enable("nscd")
    else:
        try:
            os.stat(PATH_NSCD)
            Service.disable("nscd")
        except OSError:
            pass
    return True


def read(msgcb):
    info = AuthInfo(msgcb)
    info.read()
    return info


def openfdLocked(filename, mode, perms):
    fd = None
    try:
        fd = os.open(filename, mode, perms)
        if mode == os.O_RDONLY:
            fcntl.lockf(fd, fcntl.LOCK_SH)
        else:
            fcntl.lockf(fd, fcntl.LOCK_EX)
    except OSError as err:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise IOError(err.errno, err.strerror)
    return fd


# Check for a string in an nss configuration line.
def checkNSS(configuration, candidate):
    lst = configuration.split(":", 1)
    if len(lst) > 1:
        configuration = lst[1]
    start = 0
    clen = len(candidate)
    while True:
        start = configuration.find(candidate, start)
        if start < 0:
            return None
        if start > 0 and configuration[start - 1].isalnum():
            start += clen
            continue
        if start + clen < len(configuration) and configuration[start + clen].isalnum():
            start += clen
            continue
        return start
    return None


def matchKey(line, key):
    if line.startswith(key):
        # Skip intervening whitespace.
        return line[len(key):].lstrip()
    else:
        return False


def matchKeyI(line, key):
    if line.lower().startswith(key.lower()):
        # Skip intervening whitespace.
        return line[len(key):].lstrip()
    else:
        return False


# Heuristic check whether a string is LDAP DN
def checkDN(value):
    lst = value.lstrip().split("=", 1)
    if len(lst) != 2:
        return False
    if " " in lst[0]:
        return False
    return True


def matchLine(line, key):
    return line.startswith(key)


# Make a list presentable.
def cleanList(lst):
    if not lst:
        return lst
    s = lst.replace("\t", " ")
    return ",".join(filter(None, s.split(" ")))


def matchKeyEquals(line, key):
    if line.startswith(key):
        # Skip intervening whitespace.
        return line[len(key):].lstrip(string.whitespace + "=")
    else:
        return False

def commaAppend(lst, value):
    if lst:
        return lst + "," + value
    else:
        return value


def readCache():
    return Service.isEnabled("nscd")


def isEmptyDir(path):
    try:
        lst = os.listdir(path)
    except OSError:
        # we don't know but return True anyway
        return True

    for filename in lst:
        try:
            st = os.stat(path + "/" + filename)
            if stat.S_ISREG(st.st_mode):
                return False
        except OSError:
            pass
    return True


def openLocked(filename, perms):
    return os.fdopen(openfdLocked(filename, os.O_RDWR | os.O_CREAT, perms),
                     "r+")


def getSmartcardModules():
    mods = callPKCS11Setup(["list_modules"])
    if mods == None:
        return []
    return mods


def callPKCS11Setup(options):
    try:
        child = Popen([PATH_SCSETUP] + options, stdout=PIPE, universal_newlines=True)
        lst = child.communicate()[0].split("\n")
        if child.returncode != 0:
            return None
        if lst[-1] == '':
            del lst[-1:]
    except OSError:
        return None
    return lst


def matchBaseLine(line, key):
    value = matchKey(line, key)
    if value:
        return checkDN(value)
    else:
        return False


def matchLineI(line, key):
    return line.lower().startswith(key.lower())


def krbKdc(kdclist):
    output = ""
    kdclist = kdclist.split(",")
    for kdc in kdclist:
        if kdc:
            output += "  kdc = " + kdc + "\n"
    return output


def krbAdminServer(adminservers):
    output = ""
    adminservers = adminservers.split(",")
    for adminserver in adminservers:
        if adminserver:
            output += "  admin_server = "
            output += adminserver + "\n"
    return output


def krbRealm(realm, kdclist, adminservers):
    output = ""
    if realm:
        output += " " + realm + " = {\n"
        output += krbKdc(kdclist)
        output += krbAdminServer(adminservers)
        output += " }\n\n"
    return output


def toggleSplatbindService(enable, path, name, nostart):
    if enable:
        try:
            os.stat(path)
            Service.enable(name)
            if not nostart:
                Service.stop(name)
                Service.start(name)
        except OSError:
            pass
    else:
        try:
            os.stat(path)
            if not nostart:
                try:
                    Service.stop(name)
                except OSError:
                    pass
            Service.disable(name)
        except OSError:
            pass
    return True

