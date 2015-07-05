"""
Code to create the user accounts on the system.
"""

from __future__ import with_statement, print_function

from datetime import datetime
from email.mime.text import MIMEText
import os
import sys
from subprocess import Popen, PIPE

import ldap
import ocf

from ocf import OCF_DN
from add_accounts import add_all

def _get_max_uid_number(connection):
    entries = connection.search_st(OCF_DN, ldap.SCOPE_SUBTREE, "(uid=*)",
                                   ["uidNumber"])
    uid_numbers = (int(num)
                   for entry in entries
                   for num in entry[1]["uidNumber"])

    return max(uid_numbers)

def finalize_accounts(users, options):
    users = list(users)

    if users:
        # Need to assign uid to new users
        if options.verbose:
            print("Getting current max uid ...")

        uid_start = _get_max_uid_number(options.ocf_ldap) + 1

        if options.verbose:
            print("UIDs for new users will start at {0}".format(uid_start))

        for uid, user in enumerate(users, start = uid_start):
            user["uid_number"] = uid

        add_all(users, options)
        _send_finalize_emails(users, options)
