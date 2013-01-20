#!/usr/bin/env python

"""
"If you're frightened of dieing, and you're holding on, you'll see devils
tearing your life away. But, if you've made your peace, then the devils
are really angels freeing you from the earth..." -- Jacob's Ladder

User deletion tool.
"""

import argparse
import datetime
import errno
from getpass import getpass
import os
import pexpect
import shutil
from subprocess import Popen, PIPE, check_call
import sys

from ocf import home_dir, http_dir, OCF_DN

import ldap
import ldap.sasl

def _kerberos_rm(users, options):
    kadmin = pexpect.spawn("kadmin", ["-p", "{0}/admin".format(options.admin_user)])
    kadmin.expect("kadmin> ")

    for user in users:
        kadmin.sendline("del {0}".format(user["account_name"]))

        i = 0

        while i == 0:
            i = kadmin.expect(
                ["{0}/admin@OCF.BERKELEY.EDU's Password:".format(options.admin_user),
                 "kadmin> ",
                 "kadmin: [^\n]*"])

            if i == 0:
                kadmin.sendline(options.admin_password)
            elif i == 2:
                print kadmin.match.group(0)
                kadmin.expect("kadmin> ")

    kadmin.sendline("exit")
    kadmin.expect(pexpect.EOF)

def _ldap_rm(users, options):
    for user in users:
        dn = "uid={0},{1}".format(user["account_name"], OCF_DN)

        try:
            options.ocf_ldap.delete_s(dn)
        except ldap.NO_SUCH_OBJECT:
            print "{0} does not exist in ldap".format(dn)

def _rm_user_dirs(users):
    for user in users:
        try:
            shutil.rmtree(home_dir(user["account_name"]))
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise e

        try:
            shutil.rmtree(http_dir(user["account_name"]))
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise e

def _send_finalize_emails(users, options,
                          me = "OCF staff <staff@ocf.berkeley.edu>",
                          staff = "staff@ocf.berkeley.edu"):
    """
    Notify users and staff that accounts were created.
    """

    if users and options.email:
        # Notify staff of all the created accounts
        body = "Accounts deleted on {0}:\n".format(datetime.now())

        for user in users:
            body += "{0}\n".format(user["account_name"])

        msg = MIMEText(body)
        msg["Subject"] = "Deleted OCF accounts"
        msg["From"] = me
        msg["To"] = staff

        s = Popen(["sendmail", "-t"], stdin = PIPE)
        s.communicate(msg.as_string())

def rm_users(users, options):
    _rm_user_dirs(users)
    _ldap_rm(users, options)
    _kerberos_rm(users, options)

    _send_rm_emails(users, options)

def _delete_parser():
    parser = argparse.ArgumentParser(description = "Delete user accounts.")

    parser.add_argument("-a", "--admin-user", dest = "admin_user",
                        default = os.environ.get("SUDO_USER", os.environ.get("USER", "")),
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

    if os.environ.get("USER", "") != "root":
        raise RuntimeError("Not running as superuser")

    options.ocf_ldap = ldap.initialize(options.ocf_ldap_url)
    options.ocf_ldap.simple_bind_s("", "")
    options.ocf_ldap.protocol_version = ldap.VERSION3

    options.accounts = [{"account_name": user} for user in options.accounts]

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

        rm_users(options.accounts, options)
    finally:
        check_call(["kdestroy"])

if __name__ == "__main__":
    main(sys.argv[1:])
