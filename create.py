#!/usr/bin/env python

"""
"Let there be light." -- Genesis 1:3

User creation tool.
"""

# Dependencies:
# python2.7 (Or python2.6 + python-argparse)
# python-ldap
# pycrypto

import argparse
from getpass import getpass
import os
import pexpect
import shutil
from subprocess import check_call
import sys

from filter_accounts import filter_accounts
from finalize_accounts import finalize_accounts
from utils import get_users, fancy_open, write_users

import ldap
import ldap.sasl

def _associate_calnet(account_name):
    pass

def _check_account_name(account_name):
    # do getent passwd account_name
    pass

def _email_problems():
    pass

def _finish_account_creation(src):
    now = datetime.now().strftime("%Y-%m-%d")
    directory, name = os.path.split(source)

    dest = os.path.join(directory, "..", "oldapprovedusers", "{0}.{1}".format(name, now))
    shutil.move(src, dest)

    # All this chown / chmod'ing necessary? Aren't we guaranteed to be running as root?
    os.chown(dest, getpwnam("root").pw_uid, getgrnam("root").gr_gid)
    os.chmod(dest, 0600)

    # Create the new approved.users file for future use.
    with open(src, "a"):
        pass

    os.chown(src, getpwnam("root").pw_uid, getgrnam("root").gr_gid)
    os.chmod(src, 0600)

def _create_parser():
    parser = argparse.ArgumentParser(description = "Process and create user accounts.")

    parser.add_argument("-u", "--usersfile", dest = "users_file",
                        default = "/opt/create/public/approved.users",
                        help = "Input file of approved users")
    parser.add_argument("-m", "--midapprove", dest = "mid_approve",
                        default = "/opt/create/private/mid_approved.users",
                        help = "Input file of users in mid stage of approval")
    parser.add_argument("-a", "--admin-user", dest = "admin_user",
                        default = os.environ.get("SUDO_USER", os.environ.get("USER", "")),
                        help = "User to autheticate through kerberos with")
    parser.add_argument("-i", "--interactive", dest = "interactive",
                        action = "store_true",
                        help = "Ask stdin when staff approval is required")
    parser.add_argument("-n", "--no-email", dest = "email",
                        action = "store_false",
                        help = "Don't send account creation / rejection emails")
    parser.add_argument("-l", "--logfile", dest = "log_file",
                        default = "/opt/create/public/approved.log",
                        help = "Input file of approved log")
    parser.add_argument("-p", "--priv-key", dest = "rsa_priv_key",
                        default = "/opt/create/private/private_pass.pem",
                        help = "Private key to decrypt user passwords")
    parser.add_argument("-c", "--calnetldap", dest = "calnet_ldap_url",
                        default = "ldap://ldap.berkeley.edu",
                        help = "Url of CalNet's LDAP")
    parser.add_argument("-o", "--ocfldap", dest = "ocf_ldap_url",
                        default = "ldaps://ldap.ocf.berkeley.edu",
                        help = "Url of OCF's LDAP")
    parser.add_argument("-b", "--uidlowerbound", dest = "conflict_uid_lower_bound",
                        default = 16000,
                        help = "Lower bound for OCF name collision detection")

    return parser

def main(args):
    """
    Process a file contain a list of user accounts to create.
    """

    options = _create_parser().parse_args(args = args)

    if os.environ.get("USER", "") != "root":
        raise RuntimeError("Not running as superuser")

    options.calnet_ldap = ldap.initialize(options.calnet_ldap_url)
    options.calnet_ldap.simple_bind_s("", "")
    options.calnet_ldap.protocol_version = ldap.VERSION3

    options.ocf_ldap = ldap.initialize(options.ocf_ldap_url)
    options.ocf_ldap.simple_bind_s("", "")
    options.ocf_ldap.protocol_version = ldap.VERSION3

    # Autheticate our ldap session using gssapi
    options.admin_password = \
      getpass("{0}/admin@OCF.BERKELEY.EDU's Password: ".format(options.admin_user))

    # Process the users in the mid stage of approval first
    try:
        # XXX: Use python-kerberos for this?
        kinit = pexpect.spawn("kinit {0}/admin".format(options.admin_user))
        kinit.expect("{0}/admin@OCF.BERKELEY.EDU's Password: ".format(options.admin_user))
        kinit.sendline(options.admin_password)
        kinit.expect("\n")

        if kinit.expect(["kinit: Password incorrect", pexpect.EOF]) == 0:
            print >>sys.stderr, \
              "Incorrect password for {0}/admin".format(options.admin_user)
            sys.exit()

        options.ocf_ldap.sasl_interactive_bind_s("", ldap.sasl.gssapi(""))

        with fancy_open(options.mid_approve, lock = True,
                        pass_missing = True, delete = True) as f:
            finalize_accounts(get_users(f, options), options)
    finally:
        check_call(["kdestroy"])

    # Process all of the recently requested accounts
    with fancy_open(options.users_file, lock = True,
                    pass_missing = True) as f:
        needs_approval = filter_accounts(get_users(f, options), options)

    # Write the users needing staff approval back to the users file
    with fancy_open(options.users_file, "w", lock = True) as f:
        write_users(f, [user for user, comment in needs_approval])

if __name__ == "__main__":
    main(sys.argv[1:])
