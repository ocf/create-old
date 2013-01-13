"""
Let there be light.

User creation tool.
"""

# Dependencies:
# python2.7
# python-ldap
# pycrypto

import argparse
import os
import shutil
import sys

from filter_accounts import filter_accounts
from finalize_accounts import finalize_accounts
from utils import get_users, LDAPAction, fancy_open

def _associate_calnet(account_name):
    pass

def _check_account_name(account_name):
    pass

def _email_problems():
    pass

def _finish_account_creation(src):
    now = datetime.now().strftime("%Y-%m-%d")
    directory, name = os.path.split(source)

    dest = os.path.join(directory, "..", "oldapprovedusers", "{}.{}".format(name, now))
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
                        default = "/opt/adm/approved.users",
                        help = "Input file of approved users")
    parser.add_argument("-m", "--midapprove", dest = "mid_approve",
                        default = "/opt/adm/mid_approved.users",
                        help = "Input file of users in mid stage of approval")
    parser.add_argument("-s", "--staffapprove", dest = "staff_approve",
                        default = "/opt/adm/staff_approve.users",
                        help = "Output file for users requiring manual staff approval")
    parser.add_argument("-l", "--logfile", dest = "log_file",
                        default = "/opt/adm/approved.log",
                        help = "Input file of approved log")
    parser.add_argument("-p", "--priv-key", dest = "rsa_priv_key",
                        default = "/opt/adm/pass_private.pem",
                        help = "Private key to decrypt user passwords")
    parser.add_argument("-c", "--calnetldap", dest = "calnet_ldap",
                        default = "ldap://169.229.218.90",
                        action = LDAPAction,
                        help = "Url of CalNet's LDAP")
    parser.add_argument("-o", "--ocfldap", dest = "ocf_ldap",
                        action = LDAPAction,
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

    options = _create_parser().parse_args()

    # Process the users in the mid stage of approval first
    with fancy_open(options.mid_approve, lock = True,
                    pass_missing = True) as f:
        finalize_accounts(get_users(f, options), options)

    # Process all of the recently requested accounts
    with fancy_open(options.users_file, lock = True,
                    pass_missing = True) as f:
        filter_accounts(get_users(f, options), options)

    # XXX: Move approved.users around? (_finish_account_creation...)

if __name__ == "__main__":
    main(sys.argv)
