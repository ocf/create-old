"""
Module to filter user accounts into good users, problematic users, and users that
require manual staff approval.
"""

import ldap
import os
import sys

from utils import get_log_entries, fancy_open

def _get_max_uid_number(connection):
    entries = connection.search_st("ou=People,dc=OCF,dc=Berkeley,dc=EDU",
                                   ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
    uid_numbers = (int(num)
                   for num in entry[1]["uidNumber"]
                   for entry in entries)

    return max(uid_numbers)

def _prompt_returns_yes(prompt):
    if prompt[-1] != " ":
        prompt += " "

    ret = raw_input(prompt).strip()
    if len(ret):
        ret = ret[0]

    return ret.lower() == "y"

def _filter_log_duplicates(accepted, needs_approval, rejected, options):
    """
    Filters users for account names already present in accounts.log.

    Returns new accepted, needs_approval, and rejected lists.
    """

    accepted_new = []
    needs_approval_new = []

    with open(options.log_file) as f:
        log_users = get_log_entries(f)

    user_names = set(user["account_name"] for user in users)
    log_user_names = set(user["account_name"] for user in log_users)

    for user in accepted:
        if user["account_name"] in log_user_names:
            needs_approval_new += (user, "Duplicate account name found in log file"),
        else:
            accepted_new += user,

    return accepted_new, needs_approval_new, rejected

def _filter_duplicates(key, error_str, accepted, needs_approval, rejected,
                       unique_function = lambda x: x):
    accepted_new = []
    needs_approval_new = needs_approval
    unique_values = dict()

    # Add the values for rejected requests
    for user, comment in needs_approval + rejected:
        unique_values[unique_function(user[key])] = []

    # Screen all currently-okay requests
    for user in accepted:
        value = unique_function(user[key])

        if value in unique_values:
            # Duplicate found, add this user and the other duplicates to needs_approval_new
            for other in unique_values[value]:
                needs_approval_new += (other, error_str),

            unique_values[value] = []
            needs_approval_new += (user, error_str)
        else:
            unique_values[value] = [user]

    for key, values in unique_values.items():
        accepted_new += values

    return accepted_new, needs_approval_new, rejected

def _filter_real_name_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("personal_owner", "Duplicate real name for account detected",
                              accepted, needs_approval, rejected,
                              lambda real_name: real_name.strip().lower())

def _filter_calnet_uid_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("calnet_uid", "Duplicate CalNet UID detected",
                              accepted, needs_approval, rejected)

def _filter_email_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("email", "Duplicate email address detected",
                              accepted, needs_approval, rejected)

def _filter_ocf_duplicates(accepted, needs_approval, rejected, options):
    """
    Search the OCF ldap database for matching cn entries.
    """

    base_dn = "ou=people,dc=ocf,dc=berkeley,dc=edu"
    retrieve_attrs = ["uidNumber", "cn"]

    accepted_new = []
    needs_approval_new = needs_approval

    for user in accepted:
        if user["is_group"]:
            name = entry["group_owner"]
        else:
            name = entry["personal_owner"]

        search_filter = "cn=*{}*".format(name).replace(" ", "*")
        results = options.ocf_ldap.search_st(base_dn, ldap.SCOPE_SUBTREE,
                                             search_filter, retrieve_attrs)

        if (results and
            results[0][1]["uidNumber"][0] >= options.conflict_uid_lower_bound):
            needs_approval_new += (user, "Possible existing account"),
        else:
            accepted_new += user,

    return accepted_new, needs_approval_new, rejected

def _filter_registration_status(accepted, needs_approval, rejected, options):
    """
    Check member eligibility by their CalNet registration status.

    See rules: http://wiki.ocf.berkeley.edu/membership/eligibility/
    """

    base_dn = "dc=berkeley,dc=edu"
    retrieve_attrs = ["berkeleyEduAffiliations", "displayName"]

    accepted_new = []
    needs_approval_new = needs_approval

    for user in good_users:
        # Skip CalNet registration check for group accounts
        if user["is_group"]:
            continue

        search_filter = "uid={}".format(user["calnet_uid"])

        results = options.calnet_ldap.search_st(base_dn, ldap.SCOPE_SUBTREE,
                                                search_filter, retrieve_attrs)
        if not results:
            needs_approval_new += (user, "No CalNet entry found")
            continue

        affiliation = results[0][1]["berkeleyEduAffiliations"]

        if ((("EMPLOYEE-TYPE-ACADEMIC" in affiliation or
              "EMPLOYEE-TYPE-STAFF" in affiliation) and
             "EMPLOYEE-STATUS-EXPIRED" not in affiliation)
            or
            ("STUDENT-TYPE-REGISTERED" in affiliation and
             "STUDENT-STATUS-EXPIRED" not in affiliation)
            or
            ("AFFILIATE-TYPE" in affiliation and
             "AFFILIATE-STATUS-EXPIRED" not in affiliation)):
            accepted_new += user,
        else:
            message = "CalNet status not eligible for account ({})"
            message.format(", ".join(affiliation))
            needs_approval_new += (user, message),

    return accepted_new, needs_approval_new, rejected

def _filter_usernames_manually(accepted, needs_approval, rejected, options):
    problem_users = set()
    for user in good_users:
        entry = approved_users[user]
        account_name = entry["account_name"]
        real_name = entry["personal_owner"] or entry["group_owner"]
        if not _prompt_returns_yes("Approve %s for %s?" % (account_name, real_name)):
            print "Adding %s to problem users" % user
            problem_users.add(user)
        print
    return problem_users

def _send_filter_mail(accepted, needs_approval, rejected,
                      me = "OCF staff <help@ocf.berkeley.edu>",
                      staff = "staff@ocf.berkeley.edu"):
    if accepted or needs_approval or rejected:
        body = "Account filtering run, results:\n"

        if accepted:
            body += "Automatically accepted:\n\n"

            for user in accepted:
                owner = user["group_owner" if user["is_group"] else "personal_owner"]
                body += "    {} ({})\n".format(user["account_name"], owner)

            body += "\n"
            body += "Accounts will be created next time this script runs.\n\n"

        if needs_approval:
            body += "Needs staff approval:\n\n"

            for user, comment in needs_approval:
                owner = user["group_owner" if user["is_group"] else "personal_owner"]
                body += "    {} ({}): {}\n".format(user["account_name"], owner, comment)

            body += "\n"

        if rejected:
            body += "Rejected:\n\n"

            for user, comment in rejected:
                owner = user["group_owner" if user["is_group"] else "personal_owner"]
                body += "    {} ({}): {}\n".format(user["account_name"], owner, comment)

            body += "\n"

        body += "Live lovely,\n--Account creation bot"

        # Send out the mail!
        s = smtplib.SMTP("localhost")

        msg = MIMEText(body)
        msg["Subject"] = "Account Filtering Results"
        msg["From"] = me
        msg["To"] = staff

        s.sendmail(me, [staff], msg.as_string())

        s.quit()

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

    # Check for real name duplicates
    accepted, needs_approval, rejected = \
      _filter_real_name_duplicates(accepted, needs_approval, rejected, options)

    # Check for CalNet UID duplicates
    accepted, needs_approval, rejected = \
      _filter_calnet_uid_duplicates(accepted, needs_approval, rejected, options)

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
    #   _filter_usernames_manually(accepted, needs_approval, rejected, options)

    # Need to assign uid to new users
    print "Getting current max uid ..."
    uid_start = _get_max_uid_number(options.ocf_ldap) + 1
    print "UIDs for new users will start at {}".format(uid_start)

    for user, uid in zip(accepted, xrange(uid_start, uid_start + len(accepted))):
        user["uid_number"] = uid

    with fancy_open(options.staff_approve, "a", lock = True) as f:
        write_users(f, needs_approval)

    with fancy_open(options.mid_approve, "a") as f:
        write_users(f, accepted)

    # Email out this information
    _send_filter_mail(accepted, needs_approval, rejected)
