#!/usr/bin/env python

"""
"If you're frightened of dieing, and you're holding on, you'll see devils
tearing your life away. But, if you've made your peace, then the devils
are really angels freeing you from the earth..." -- Jacob's Ladder

User deletion tool.
"""

import os
import ldap
import shutil
from subprocess import PIPE, Popen, check_call
import sys

from ocf import home_dir, http_dir, OCF_DN

def _kerberos_rm(users, options)
    kadmin = Popen(["kadmin", "-p", "{}/admin".format(options.admin_user)], stdin = PIPE)
    first = True

    for user in users:
        # Calling subprocess.Popen here because we don't have a decent
        # kerberos python module for administration commands
        # Call the add command
        # XXX: Use pexpect here.
        kadmin.stdin.write("delete {}\n".format(user["account_name"]))

        if first:
            # Autheticate the first time
            kadmin.stdin.write("{}\n".format(options.admin_password))
            first = False

    kadmin.communicate()

    if kadmin.returncode != 0:
        raise RuntimeError("kdamin returned non-zero exit code: " + kadmin.returncode)

def _ldap_rm(users, options):
    for user in users:
        dn = "uid={},{}".format(user["account_name"], OCF_DN)
        options.ocf_ldap.delete_s(dn)

def _rm_user_dirs(users):
    for user in users:
        shutil.rmtree(home_dir(user["account_name"]))
        shutil.rmtree(http_dir(user["account_name"]))

def rm_user(users, options):
    _rm_user_dirs(users)
    _ldap_rm(users, options)
    _kerberos_rm(users, options)

def _delete_parser():
    parser = argparse.ArgumentParser(description = "Delete user accounts.")
    parser.add_argument("-a", "--admin-user", dest = "admin_user",
                        default = os.environ["SUDO_USER"],
                        help = "User to autheticate through kerberos with")
    parser.add_argument("-n", "--no-email", dest = "email",
                        action = "store_false",
                        help = "Don't send account creation / rejection emails")
    parser.add_argument("-o", "--ocfldap", dest = "ocf_ldap_url",
                        default = "ldaps://ldap.ocf.berkeley.edu",
                        help = "Url of OCF's LDAP")
    parser.add_argument("accounts", nargs = "+",
                        help = "User accounts to delete")

    return parser

def main(args):
    options = _delete_parser().parse_args(args = args)

    options.ocf_ldap = ldap.initialize(options.ocf_ldap_url)
    options.ocf_ldap.simple_bind_s("", "")
    options.ocf_ldap.protocol_version = ldap.VERSION3

    # Autheticate our ldap session using gssapi
    options.admin_password = \
      getpass("{}/admin@OCF.BERKELEY.EDU's Password: ".format(options.admin_user))

    # Process the users in the mid stage of approval first
    try:
        # XXX: Use python-kerberos for this?
        kinit = Popen(["kinit", "{}/admin".format(options.admin_user)], stdin = PIPE)
        kinit.stdin.write("{}\n".format(options.admin_password))
        kinit.communicate()

        if kinit.returncode != 0:
            raise RuntimeError("kinit failed with exit code: " + kinit.returncode)

        options.ocf_ldap.sasl_interactive_bind_s("", ldap.sasl.gssapi(""))

        rm_users(options.accounts, options)
    finally:
        check_call(["kdestroy"])

if __name__ == "__main__":
    main(sys.argv)
