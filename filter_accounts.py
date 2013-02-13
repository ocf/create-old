"""
Module to filter user accounts into good users, problematic users, and users that
require manual staff approval.
"""

from email.mime.text import MIMEText
import ldap
import os
from subprocess import PIPE, Popen
import sys

from ocf import OCF_DN
from utils import get_log_entries, fancy_open, write_users

def _staff_approval(user, error_str, accepted, needs_approval, rejected, options):
    if not options.interactive:
        needs_approval.append((user, error_str))
        return

    prompt = "{0}\n{1} ({2})\n"
    prompt += "Approve this account? "
    prompt = prompt.format(error_str, user["account_name"], user["owner"])

    ret = raw_input(prompt).strip().lower()

    if ret in ["y", "yes"]:
        accepted.append(user)
    elif ret in ["n", "no"]:
        rejected.append((user, error_str))
    else:
        needs_approval.append((user, error_str))

def _filter_log_duplicates(accepted, needs_approval, rejected, options):
    """
    Filters users for account names already present in accounts.log.

    Returns new accepted, needs_approval, and rejected lists.
    """

    accepted_new = []
    needs_approval_new = needs_approval
    rejected_new = rejected

    with open(options.log_file) as f:
        log_users = get_log_entries(f)

        log_user_names = dict()

        for user in log_users:
            name = user["account_name"]

            if name in log_user_names:
                log_user_names[name] += 1
            else:
                log_user_names[name] = 1

    for user in accepted:
        if log_user_names.get(user["account_name"], 0) > 1:
            _staff_approval(user, "Duplicate account name found in log file",
                            accepted_new, needs_approval_new, rejected_new, options)
        else:
            accepted_new += user,

    return accepted_new, needs_approval_new, rejected_new

def _filter_duplicates(key, error_str, accepted, needs_approval, rejected, options,
                       unique_function = lambda x: x):
    accepted_new = []
    needs_approval_new = needs_approval
    rejected_new = rejected

    unique_values = dict()

    # Add the values for rejected requests
    for user, comment in needs_approval + rejected:
        value = unique_function(user[key])

        if value:
            unique_values[value] = []

    # Screen all currently-okay requests
    for user in accepted:
        value = unique_function(user[key])

        if value in unique_values:
            if not value:
                unique_values[value].append(user)
                continue

            # Duplicate found, add this user and the other duplicates to needs_approval_new
            for other in unique_values[value]:
                _staff_approval(other, error_str,
                                accepted_new, needs_approval_new, rejected_new, options)

            unique_values[value] = []
            _staff_approval(user, error_str,
                            accepted_new, needs_approval_new, rejected_new, options)
        else:
            unique_values[value] = [user]

    for key, values in unique_values.items():
        accepted_new += values

    return accepted_new, needs_approval_new, rejected_new

def _fix_name(real_name):
    return real_name.strip().lower()

def _filter_account_name_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("account_name", "Duplicate account name detected",
                              accepted, needs_approval, rejected, options, _fix_name)

def _filter_owner_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("owner", "Duplicate owner detected",
                              accepted, needs_approval, rejected, options, _fix_name)

def _filter_university_uid_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("university_uid", "Duplicate CalNet UID detected",
                              accepted, needs_approval, rejected, options)

def _filter_email_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("email", "Duplicate email address detected",
                              accepted, needs_approval, rejected, options)

def _filter_ocf_duplicates(accepted, needs_approval, rejected, options):
    """
    Search the OCF ldap database for matching cn entries.
    """

    retrieve_attrs = ["uidNumber", "cn"]

    accepted_new = []
    needs_approval_new = needs_approval
    rejected_new = rejected

    for user in accepted:
        search_filter = "calNetuid={0}".format(user["university_uid"])
        results = options.ocf_ldap.search_st(OCF_DN, ldap.SCOPE_SUBTREE,
                                             search_filter, retrieve_attrs)

        if (results and
            results[0][1]["uidNumber"][0] >= options.conflict_uid_lower_bound):
            _staff_approval(user, "Possible existing account",
                            accepted_new, needs_approval_new, rejected_new, options)
        else:
            accepted_new += user,

    return accepted_new, needs_approval_new, rejected_new

def _filter_registration_status(accepted, needs_approval, rejected, options):
    """
    Check member eligibility by their CalNet registration status.

    See rules: http://wiki.ocf.berkeley.edu/membership/eligibility/
    """

    base_dn = "dc=berkeley,dc=edu"
    retrieve_attrs = ["berkeleyEduAffiliations", "displayName"]

    accepted_new = []
    needs_approval_new = needs_approval
    rejected_new = rejected

    for user in accepted:
        # Skip CalNet registration check for group accounts
        if user["is_group"]:
            accepted_new += user,
            continue

        search_filter = "uid={0}".format(user["university_uid"])

        results = options.calnet_ldap.search_st(base_dn, ldap.SCOPE_SUBTREE,
                                                search_filter, retrieve_attrs)
        if not results:
            _staff_approval(user, "No CalNet entry found", accepted_new,
                            needs_approval_new, rejected_new, options)
            continue

        affiliation = results[0][1]["berkeleyEduAffiliations"]

        allowed_affiliates = set(["AFFILIATE-TYPE-CONSULTANT",
                                  "AFFILIATE-TYPE-LBLOP STAFF",
                                  "AFFILIATE-TYPE-VISITING SCHOLAR",
                                  "AFFILIATE-TYPE-VOLUNTEER",
                                  "AFFILIATE-TYPE-HHMI RESEARCHER",
                                  "AFFILIATE-TYPE-VISITING STU RESEARCHER",
                                  "AFFILIATE-TYPE-LBL/DOE POSTDOC",
                                  "AFFILIATE-TYPE-TEMP AGENCY",
                                  "AFFILIATE-TYPE-COMMITTEE MEMBER",
                                  "AFFILIATE-TYPE-STAFF OF UC/OP/AFFILIATED ORGS",
                                  "AFFILIATE-TYPE-CONTRACTOR"
                                  "AFFILIATE-TYPE-CONCURR ENROLL"])

        if ((("EMPLOYEE-TYPE-ACADEMIC" in affiliation or
              "EMPLOYEE-TYPE-STAFF" in affiliation) and
             "EMPLOYEE-STATUS-EXPIRED" not in affiliation)
            or
            ("STUDENT-TYPE-REGISTERED" in affiliation and
             "STUDENT-STATUS-EXPIRED" not in affiliation)
            or
            (set(affiliation).intersection(allowed_affiliates) and
             "AFFILIATE-STATUS-EXPIRED" not in affiliation)):
            accepted_new += user,
        else:
            message = "CalNet status not eligible for account ({0})"
            message = message.format(", ".join(affiliation))

            _staff_approval(user, message,
                            accepted_new, needs_approval_new, rejected_new, options)

    return accepted_new, needs_approval_new, rejected_new

def _filter_usernames(accepted, needs_approval, rejected, options):
    accepted_new = []
    needs_approval_new = needs_approval
    rejected_new = rejected

    for user in accepted:
        message = "{0} is not an allowed username for {1}".format(user["account_name"],
                                                                  user["owner"])
        _staff_approval(user, message,
                        accepted_new, needs_approval_new, rejected_new, options)

    return accepted_new, needs_approval_new, rejected_new

def _send_filter_mail(accepted, needs_approval, rejected, options,
                      me = "OCF staff <help@ocf.berkeley.edu>",
                      staff = "staff@ocf.berkeley.edu"):
    if (accepted or needs_approval or rejected) and options.email:
        body = "Account filtering run, results:\n\n"

        if accepted:
            body += "Automatically accepted (Accounts will be created "
            body += "next time this script runs):\n\n"

            for user in accepted:
                body += "    {0} ({1})\n".format(user["account_name"], user["owner"])

            body += "\n"

        if needs_approval:
            body += "Needs staff approval:\n\n"

            for user, comment in needs_approval:
                body += "    {0} ({1}): {2}\n".format(user["account_name"],
                                                      user["owner"], comment)

            body += "\n"

        if rejected:
            body += "Rejected:\n\n"

            for user, comment in rejected:
                body += "    {0} ({1}): {2}\n".format(user["account_name"],
                                                      user["owner"], comment)

            body += "\n"

        body += "Live lovely,\n"
        body += "--Account creation bot\n"

        # Send out the mail!
        msg = MIMEText(body)
        msg["Subject"] = "Account Filtering Results"
        msg["From"] = me
        msg["To"] = staff

        s = Popen(["sendmail", "-t"], stdin = PIPE)
        s.communicate(msg.as_string())

def filter_accounts(users, options):
    """
    Filter accounts into auto-accepted, needs-staff-approval, and rejected.
    """

    accepted = list(users)
    needs_approval = []
    rejected = []

    # Check for log duplicates
    accepted, needs_approval, rejected = \
      _filter_log_duplicates(accepted, needs_approval, rejected, options)

    # Check for account name duplicates
    accepted, needs_approval, rejected = \
      _filter_account_name_duplicates(accepted, needs_approval, rejected, options)

    # Check for owner duplicates
    accepted, needs_approval, rejected = \
      _filter_owner_duplicates(accepted, needs_approval, rejected, options)

    # Check for CalNet UID duplicates
    accepted, needs_approval, rejected = \
      _filter_university_uid_duplicates(accepted, needs_approval, rejected, options)

    # Check for email address duplicates
    accepted, needs_approval, rejected = \
      _filter_email_duplicates(accepted, needs_approval, rejected, options)

    # Check for OCF existing account duplicates
    accepted, needs_approval, rejected = \
      _filter_ocf_duplicates(accepted, needs_approval, rejected, options)

    # Check CalNet registration status
    accepted, needs_approval, rejected = \
      _filter_registration_status(accepted, needs_approval, rejected, options)

    # Check requested usernames
    # accepted, needs_approval, rejected = \
    #   _filter_usernames(accepted, needs_approval, rejected, options)

    # Write the accepted users to a staging file, allowing them marinate
    with fancy_open(options.mid_approve, "a", lock = True) as f:
        write_users(f, accepted)

    # Email out this information
    _send_filter_mail(accepted, needs_approval, rejected, options)

    return needs_approval
