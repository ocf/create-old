"""
"""

from __future__ import with_statement, print_function

import base64
from grp import getgrnam
import pexpect
from subprocess import check_call
import os
import tempfile
import sys

import ldap
import ldap.modlist

from utils import decrypt_password, null_out
from ocf import home_dir, http_dir, OCF_DN, log_creation

# See https://rt.ocf.berkeley.edu/Ticket/Display.html?id=638 for a list of
# all the things to copy over

def _add_all_kerberos(users, dumps, options, domain = "OCF.BERKELEY.EDU"):
    principal = "{0}/admin".format(options.admin_user)
    args = ["--principal=" + principal]
    if options.keytab:
        args.append("--keytab=" + options.keytab)
    kadmin = pexpect.spawn("kadmin", args)
    kadmin.expect("kadmin> ")

    for user, dump in zip(users, dumps):
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

def _add_all_ldap(users, dumps, connection, shell = "/bin/bash"):
    for user, dumps in zip(users, dumps):
        dn = "uid={0},{1}".format(user["account_name"], OCF_DN)
        attrs = {
            "objectClass": ["ocfAccount", "account", "posixAccount"],
            "cn": [user["owner"]],
            "uid": [user["account_name"]],
            "uidNumber": [str(user["uid_number"])],
            "gidNumber": [str(getgrnam("ocf").gr_gid)],
            "homeDirectory": [home_dir(user["account_name"])],
            "loginShell": [shell],
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
    check_call(["nscd", "-i", "passwd"], stdout = null_out())

def _add_ldap_groups(user, options, dump = None):
    pass

def _add_home_dir(user, dump = None):
    # Probably want to copy their homedir to a tmp directory...or maybe
    # we can just forgo the dump/add paradigm for files
    home = home_dir(user["account_name"])
    check_call(
        ["sudo", "install", "-d", "--mode=0700", "--group=ocf",
         "--owner=" + user["account_name"], home],
        stdout = sys.stderr
        )

    if dump is None:
        for name in [".cshrc", ".bashrc", ".bash_profile", ".bash_logout"]:
            path = os.path.join(os.path.dirname(__file__), "rc", name)
            check_call(
                ["sudo", "install", "--mode=0600", "--group=ocf",
                 "--owner=" + user["account_name"], path, home],
                stdout = sys.stderr
                )

def _add_web_dir(user, dump = None):
    # See comments in _add_home_dir
    http = http_dir(user["account_name"])
    check_call(
        ["sudo", "install", "-d", "--mode=0000", "--group=ocf",
         "--owner=" + user["account_name"], http],
        stdout = sys.stderr
        )

def _add_forward(user, dump = None):
    if dump is None and user["forward"]:
        forward = os.path.join(home_dir(user["account_name"]), ".forward")

        tmp = tempfile.mkstemp()[1]

        with open(tmp, "w") as f:
            f.write(user["email"] + "\n")

        check_call(
            ["sudo", "install", "--group=ocf", "--owner=" + user["account_name"],
             tmp, forward],
            stdout = sys.stderr
            )

def _add_postgresql(user, options, dump = None):
    """
    Re-add a user's postgresql database.
    """
    if dump is not None:
        pass

def _add_mysql(user, options, dump = None):
    """
    Adds a user's mysql tables back into the OCF database.
    """
    # Access the new username with user["username"]
    pass

def _add_tsunami_crontab(user, dump, options):
    pass

def _add_crontabs(user, dump, options):
    _add_tsunami_crontab(user, dump["tsunami"], options)

def _add_pykota(user, dump, options):
    pass

def _add_rt(user, new_username, dump, options):
    # We care enough to support staff?
    pass

def _add_wiki(user, dump, options):
    # We care enough to support staff?
    pass

def _add_mail(user, dump, options):
    # Is this not all in the homedir?
    pass

def _add_user_info(user, dump, options):
    pass

def add_all(users, options, dumps = None):
    if dumps:
        assert len(dumps) == len(users)
    else:
        dumps = [None] * len(users)

    if options.verbose:
        print("Creating all kerberos and ldap accounts")

    _add_all_kerberos(users, dumps, options)
    _add_all_ldap(users, dumps, options.ocf_ldap)

    for user, dump in zip(users, dumps):
        if options.verbose:
            print("Creating new account, {0}, for {1}"
                  .format(user["account_name"], user["owner"]))

        _add_home_dir(user, dump = dump)
        _add_web_dir(user, dump = dump)
        _add_forward(user, dump = dump)

        log_creation(user, options)
