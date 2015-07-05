import base64
from grp import getgrnam
import pexpect
from subprocess import check_call
import os
import tempfile
import sys

import ldap
import ldap.modlist

from utils import decrypt_password
from ocf import log_creation

import ocflib.account.utils as utils
import ocflib.constants as constants

# See https://rt.ocf.berkeley.edu/Ticket/Display.html?id=638 for a list of
# all the things to copy over

def _add_all_kerberos(users, options, domain = "OCF.BERKELEY.EDU"):
    principal = "{0}/admin".format(options.admin_user)
    args = ["--principal=" + principal]
    if options.keytab:
        args.append("--keytab=" + options.keytab)
    kadmin = pexpect.spawn("kadmin", args)
    kadmin.expect("kadmin> ")

    for user in users:
        # We don't have a decent kerberos python module for administration
        # commands :(
        user_password = \
          decrypt_password(base64.b64decode(user["password"]),
                           options.rsa_priv_key).decode()

        # Call the add command
        kadmin.sendline("add --use-defaults {0}".format(user["account_name"]))

        i = 0

        while i != 4:
            i = kadmin.expect(
                ["{0}@{1}'s Password:".format(principal, domain),
                 "{0}@{1}'s Password:".format(user["account_name"], domain),
                 "Verifying - {0}@{1}'s Password:".format(user["account_name"],
                                                          domain),
                 "kadmin: [^\n]*",
                 "kadmin> "])

            if i == 0:
                kadmin.sendline(options.admin_password)
            elif i in [1, 2]:
                kadmin.sendline(user_password)
            elif i == 3:
                print(kadmin.match.group(0), file = sys.stderr)

    kadmin.sendline("exit")
    kadmin.expect(pexpect.EOF)

def _add_all_ldap(users, connection, shell="/bin/bash"):
    for user in users:
        dn = "uid={},{}".format(user["account_name"], constants.OCF_LDAP_PEOPLE)
        attrs = {
            "objectClass": ["ocfAccount", "account", "posixAccount"],
            "cn": [user["owner"]],
            "uid": [user["account_name"]],
            "uidNumber": [str(user["uid_number"])],
            "gidNumber": [str(getgrnam("ocf").gr_gid)],
            "homeDirectory": [utils.home_dir(user["account_name"])],
            "loginShell": [shell],
            "mail": [user["email"]],
            "userPassword": [str("{SASL}" + user["account_name"] + "@OCF.BERKELEY.EDU")]
        }

        if not user["is_group"]:
            if "university_uid" in user:
                attrs["calnetUid"] = [str(user["university_uid"])]
            else:
                raise KeyError("User does not have university uid set")
        else:
            if "university_uid" in user:
                attrs["callinkOid"] = [str(user["university_uid"])]

        # Enter it into LDAP
        ldif = ldap.modlist.addModlist(attrs)
        try:
            connection.add_s(dn, ldif)
        except ldap.ALREADY_EXISTS:
            print("LDAP account already exists", file = sys.stderr)

    # Invalidate the local cache so we can chown their files later
    # (this is probably not necessary since nscd won't cache "DNE" responses)
    check_call(["nscd", "-i", "passwd"], stderr=open(os.devnull, "w"))


def add_all(users, options):
    _add_all_kerberos(users, options)
    _add_all_ldap(users, options.ocf_ldap)

    for user in users:
        log_creation(user, options)
