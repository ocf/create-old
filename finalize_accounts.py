"""
Code to create the user accounts on the system.
"""

from __future__ import with_statement, print_function

from datetime import datetime
from email.mime.text import MIMEText
import os
from subprocess import Popen, PIPE

import ldap

from ocf import home_dir, http_dir, OCF_DN
from utils import fancy_open
from add_accounts import add_all

ACCOUNT_CREATED_LETTER = \
  os.path.join(os.path.dirname(__file__), "txt", "acct.created.letter")

def _send_finalize_emails(users, options,
                          me = "OCF Staff <staff@ocf.berkeley.edu>",
                          reply_to = "help@ocf.berkeley.edu",
                          staff = "sm@ocf.berkeley.edu"):
    """
    Notify users and staff that accounts were created.
    """

    if users and options.email:
        created_text = open(ACCOUNT_CREATED_LETTER).read()

        for user in users:
            text = created_text.format(account_name = user["account_name"])
            msg = MIMEText(text)
            msg["Subject"] = "OCF account created"
            msg["From"] = me
            msg["Reply-To"] = reply_to
            msg["To"] = user["email"]

            s = Popen(["sendmail", "-t"], stdin = PIPE)
            s.communicate(msg.as_string())

        # Notify staff of all the created accounts
        user = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
        body = "Accounts created on {0} by {1}:\n".format(datetime.now(), user)

        for user in users:
            body += "{0}: {1}\n".format(user["account_name"], user["owner"])

        msg = MIMEText(body)
        msg["Subject"] = "Created OCF accounts"
        msg["From"] = me
        msg["To"] = staff

        s = Popen(["sendmail", "-t"], stdin = PIPE)
        s.communicate(msg.as_string())

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
        print("Getting current max uid ...")
        uid_start = _get_max_uid_number(options.ocf_ldap) + 1
        print("UIDs for new users will start at {0}".format(uid_start))

        for uid, user in enumerate(users, start = uid_start):
            user["uid_number"] = uid

        add_all(users, options, verbose = True)
        _send_finalize_emails(users, options)
