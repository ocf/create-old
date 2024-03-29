"""
Filter user account requests.

Separate account requests into good users, problematic users, and users
that require manual staff approval.

"""
from __future__ import print_function, with_statement

import os
import re
from difflib import SequenceMatcher
from itertools import permutations
from math import factorial
from subprocess import PIPE, Popen

import ldap

import ocf
from utils import fancy_open, get_log_entries, irc_alert, write_users


ACCOUNT_REJECTED_LETTER = \
    os.path.join(os.path.dirname(__file__), "txt", "acct.rejected.letter")


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


def _filter_log_duplicates(accepted, needs_approval, rejected, options):
    """
    Filter users for account names already present in accounts.log.

    Return new accepted, needs_approval, and rejected lists.

    """
    accepted_new = []
    needs_approval_new = list(needs_approval)
    rejected_new = list(rejected)

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
                            accepted_new, needs_approval_new, rejected_new,
                            options)
        else:
            accepted_new += user,

    return accepted_new, needs_approval_new, rejected_new


def _filter_duplicates(key, error_str, accepted, needs_approval, rejected,
                       options, unique_function=lambda x: x):
    accepted_new = []
    needs_approval_new = list(needs_approval)
    rejected_new = list(rejected)

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
            if not value or value in [0]:
                unique_values[value].append(user)
                continue

            # Duplicate found, add this user and the other duplicates to
            # needs_approval_new.
            for other in unique_values[value]:
                _staff_approval(other, error_str, accepted_new,
                                needs_approval_new, rejected_new, options)

            unique_values[value] = []
            _staff_approval(user, error_str, accepted_new, needs_approval_new,
                            rejected_new, options)
        else:
            unique_values[value] = [user]

    for key, values in unique_values.items():
        accepted_new += values

    return accepted_new, needs_approval_new, rejected_new


def _fix_name(real_name):
    return real_name.strip().lower()


def _filter_account_name_duplicates(accepted, needs_approval, rejected,
                                    options):
    return _filter_duplicates("account_name",
                              "Duplicate account name detected",
                              accepted, needs_approval, rejected, options,
                              _fix_name)


def _filter_owner_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("owner", "Duplicate owner detected",
                              accepted, needs_approval, rejected, options,
                              _fix_name)


def _filter_university_uid_duplicates(accepted, needs_approval, rejected,
                                      options):
    return _filter_duplicates("university_uid",
                              "Duplicate CalNet UID detected",
                              accepted, needs_approval, rejected, options)


def _filter_email_duplicates(accepted, needs_approval, rejected, options):
    return _filter_duplicates("email", "Duplicate email address detected",
                              accepted, needs_approval, rejected, options)


def _filter_ocf_duplicates(accepted, needs_approval, rejected, options):
    """Search the OCF LDAP database for matching cn entries."""
    retrieve_attrs = ["uidNumber", "cn"]

    accepted_new = []
    needs_approval_new = list(needs_approval)
    rejected_new = list(rejected)

    for user in accepted:
        if user["is_group"] and user["university_uid"] in ["0"]:
            accepted_new += user,
            continue

        field = "callinkOid" if user["is_group"] else "calnetUid"
        search_filter = "{0}={1}".format(field, user["university_uid"])
        results = options.ocf_ldap.search_st(ocf.OCF_DN, ldap.SCOPE_SUBTREE,
                                             search_filter, retrieve_attrs)
        uidnumber = results and results[0][1]["uidNumber"][0]

        if uidnumber and uidnumber >= options.conflict_uid_lower_bound:
            _staff_approval(user, "Possible existing account",
                            accepted_new, needs_approval_new, rejected_new,
                            options)
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
    needs_approval_new = list(needs_approval)
    rejected_new = list(rejected)

    for user in accepted:
        # Skip CalNet registration check for group accounts
        if user["is_group"] or user["university_uid"] > 9999999:
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

        allowed_affiliates = set([
            "AFFILIATE-TYPE-CONSULTANT",
            "AFFILIATE-TYPE-LBLOP STAFF",
            "AFFILIATE-TYPE-VISITING SCHOLAR",
            "AFFILIATE-TYPE-VOLUNTEER",
            "AFFILIATE-TYPE-HHMI RESEARCHER",
            "AFFILIATE-TYPE-VISITING STU RESEARCHER",
            "AFFILIATE-TYPE-LBL/DOE POSTDOC",
            "AFFILIATE-TYPE-TEMP AGENCY",
            "AFFILIATE-TYPE-COMMITTEE MEMBER",
            "AFFILIATE-TYPE-STAFF OF UC/OP/AFFILIATED ORGS",
            "AFFILIATE-TYPE-CONTRACTOR",
            "AFFILIATE-TYPE-CONCURR ENROLL",
        ])

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

            _staff_approval(user, message, accepted_new, needs_approval_new,
                            rejected_new, options)

    return accepted_new, needs_approval_new, rejected_new


def _filter_restricted_names(accepted, needs_approval, rejected, options):
    accepted_new = []
    needs_approval_new = list(needs_approval)
    rejected_new = list(rejected)

    # Some bad words, not comprehensive
    bad = {"expletive": ["fuck", "shit", "cunt", "crap", "bitch", "hell",
                         "ass", "dick"],
           "restricted": ["ocf", "ucb", "cal"]}

    for user in accepted:
        if any(word in user["account_name"]
               for restricted_type, words in bad.items()
               for word in words):
            bad_list = ", ".join("{0} ({1})".format(word, restricted_type)
                                 for restricted_type, words in bad.items()
                                 for word in words
                                 if word in user["account_name"])

            message = "{0} not allowed in username: {1}".format(
                bad_list, user["account_name"])

            _staff_approval(user, message, accepted_new,
                            needs_approval_new, rejected_new,
                            options)
        else:
            accepted_new += user,

    return accepted_new, needs_approval_new, rejected_new


def _filter_real_names(accepted, needs_approval, rejected, options):

    accepted_new = []
    needs_approval_new = list(needs_approval)
    rejected_new = list(rejected)

    threshold = 1

    for user in accepted:
        if similarity(user["owner"], user["account_name"]) > threshold:
            message = "Username {0} not based on real name {1}".format(
                user["account_name"], user["owner"])

            _staff_approval(user, message, accepted_new,
                            needs_approval_new, rejected_new,
                            options)
        else:
            accepted_new += user,

    return accepted_new, needs_approval_new, rejected_new


def _send_rejection_mail(rejected, options):
    if rejected and options.email:
        rejected_text = open(ACCOUNT_REJECTED_LETTER).read()
        os.environ["REPLYTO"] = ocf.MAIL_FROM_HELP

        for user, comment in rejected:
            body = rejected_text.format(account_name=user["account_name"],
                                        comment=comment)
            s = Popen(["mail", "-a", "From: " + ocf.MAIL_FROM_HELP, "-s",
                       "OCF Account Request Rejected", user["email"]],
                      stdin=PIPE)
            s.communicate(body)


def similarity(realname, username):
    """
    Return a count of the edits that turn realname into username.

    Count the number of replacements and insertions (*ignoring* deletions)
    for the minimum number of edits (*including* deletions) that turn any of
    the permutations of words orderings or initialisms of realname into
    username, using the built-in difflib.SequenceMatcher class.
    SequenceMatcher finds the longest continguous matching subsequence and
    continues this process recursively.

    This is usually the edit distance with zero deletion cost, but is
    intentionally greater for longer realnames with short matching
    subsequences, which are likely coincidental.

    For most usernames based on real names, this number is 0.

    """
    # The more words in realname, the more permutations. O(n!) is terrible!
    max_words = 8
    max_iterations = factorial(max_words)

    words = re.findall("\w+", realname)
    initials = [word[0] for word in words]

    if len(words) > max_words:
        print("Not trying all permutations of '{}' for similarity.".format(
              realname))

    distances = []
    for sequence in [words, initials]:
        for (i, permutation) in enumerate(permutations(sequence)):
            if i > max_iterations:
                break
            s = "".join(permutation).lower()
            matcher = SequenceMatcher(None, s, username)
            edits = matcher.get_opcodes()
            distance = sum(edit[4] - edit[3]
                           for edit in edits
                           if edit[0] in ["replace", "insert"])
            if distance == 0:
                # Edit distance cannot be smaller than 0, so return early.
                return 0
            distances.append(distance)
    return min(distances)


def filter_accounts(users, options):
    """Filter accounts into accepted, needs-staff-approval, and rejected."""
    accepted = list(users)
    needs_approval = []
    rejected = []

    # Check for log duplicates
    # accepted, needs_approval, rejected = \
    #   _filter_log_duplicates(accepted, needs_approval, rejected, options)

    # Check for account name duplicates
    accepted, needs_approval, rejected = \
        _filter_account_name_duplicates(accepted, needs_approval, rejected,
                                        options)

    # Check for owner duplicates
    accepted, needs_approval, rejected = \
        _filter_owner_duplicates(accepted, needs_approval, rejected, options)

    # Check for CalNet UID duplicates
    accepted, needs_approval, rejected = \
        _filter_university_uid_duplicates(accepted, needs_approval, rejected,
                                          options)

    # Check for email address duplicates
    # accepted, needs_approval, rejected = \
    #   _filter_email_duplicates(accepted, needs_approval, rejected, options)

    # Check for OCF existing account duplicates
    accepted, needs_approval, rejected = \
        _filter_ocf_duplicates(accepted, needs_approval, rejected,
                               options)

    # Check CalNet registration status
    accepted, needs_approval, rejected = \
        _filter_registration_status(accepted, needs_approval, rejected,
                                    options)

    # Check for expletives and restrictions in requested usernames
    accepted, needs_approval, rejected = \
        _filter_restricted_names(accepted, needs_approval, rejected, options)

    # Check that requested username is based on real name
    accepted, needs_approval, rejected = \
        _filter_real_names(accepted, needs_approval, rejected, options)

    # Write the accepted users to a staging file, allowing them marinate
    with fancy_open(options.mid_approve, "a", lock=True) as f:
        write_users(f, accepted)

    # Email out this information
    _send_rejection_mail(rejected, options)

    return needs_approval
