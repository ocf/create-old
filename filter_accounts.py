"""
Filter user account requests.

Separate account requests into good users, problematic users, and users
that require manual staff approval.

"""
import os
import re

import ldap

import ocf
from utils import fancy_open, get_log_entries, irc_alert, write_users


def _staff_approval(user, error_str, accepted, needs_approval, rejected,
                    options):
    if not options.interactive:
        needs_approval.append((user, error_str))
        return False

    prompt = "{0}\n{1} ({2})\n"
    prompt += "Approve this account? [yes/no/ignore] "
    prompt = prompt.format(error_str, user["account_name"], user["owner"])

    ret = raw_input(prompt).strip().lower()

    if ret in ["y", "yes"]:
        accepted.append(user)
        return True
    elif ret in ["n", "no"]:
        irc_alert("`{}` ({}) rejected by `{}` ({})".format(
            user["account_name"], user["owner"],
            os.environ.get('SUDO_USER', 'root'), error_str))
        rejected.append((user, error_str))
        return False
    else:
        needs_approval.append((user, error_str))
        return False
