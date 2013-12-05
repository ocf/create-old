#!/usr/bin/env python

"""
"If you're frightened of dieing, and you're holding on, you'll see devils
tearing your life away. But, if you've made your peace, then the devils
are really angels freeing you from the earth..." -- Jacob's Ladder

User deletion tool.
"""

from __future__ import with_statement, print_function

import argparse
from datetime import datetime
from email.mime.text import MIMEText
from getpass import getpass, getuser
import os
from subprocess import Popen, PIPE, check_call
import sys

import ldap
import ldap.sasl

from rm_accounts import rm_all
from utils import kinit

def _send_rm_emails(users, options, staff = "sm@ocf.berkeley.edu"):
    """
    Notify users and staff that accounts were deleted.
    """

    if users and options.email:
        # Notify staff of all the created accounts
        body = "Accounts deleted on {0}:\n".format(datetime.now())

        for user in users:
            body += "{0}\n".format(user["account_name"])

        s = Popen(["mail", "-s", "Deleted OCF Accounts", staff], stdin = PIPE)
        s.communicate(body)

def _delete_parser():
    parser = argparse.ArgumentParser(description = "Delete user accounts.")

    parser.add_argument("-a", "--admin-user", dest = "admin_user",
                        default = os.environ.get("SUDO_USER", getuser()),
                        help = "User to autheticate through kerberos with")
    parser.add_argument("-n", "--no-email", dest = "email",
                        action = "store_false",
                        help = "Don't send account creation / rejection emails")
    parser.add_argument("-o", "--ocfldap", dest = "ocf_ldap_url",
                        default = "ldaps://ldap.ocf.berkeley.edu",
                        help = "Url of OCF's LDAP")
    parser.add_argument("accounts", metavar = "account", nargs = "+",
                        help = "User account to delete")

    return parser

def main(args):
    options = _delete_parser().parse_args(args = args)

    user = getuser()
    if user not in ["root", "create"]:
        raise RuntimeError("Not running as superuser: " + user)

    options.ocf_ldap = ldap.initialize(options.ocf_ldap_url)
    options.ocf_ldap.simple_bind_s("", "")
    options.ocf_ldap.protocol_version = ldap.VERSION3

    accounts = [{"account_name": user} for user in options.accounts]

    # Autheticate our ldap session using gssapi
    options.admin_password = \
      getpass("{0}/admin@OCF.BERKELEY.EDU's Password: ".format(options.admin_user))

    # Process the users in the mid stage of approval first
    try:
        kinit("{0}/admin".format(options.admin_user), options.admin_password)
        options.ocf_ldap.sasl_interactive_bind_s("", ldap.sasl.gssapi(""))

        rm_all(accounts, options)
        _send_rm_emails(accounts, options)
    finally:
        check_call(["kdestroy"])

if __name__ == "__main__":
    main(sys.argv[1:])
