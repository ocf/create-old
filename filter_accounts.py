#!/usr/bin/env python

import ldap
import os
import sys

from utils import get_log_entries

def _get_max_uid_number(connection):
    entries = connection.search_st("ou=People,dc=OCF,dc=Berkeley,dc=EDU",
                                   ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
    uid_numbers = (int(num)
                   for num in entry[1]["uidNumber"]
                   for entry in entries)

    return max(uid_numbers)

def prompt_returns_yes(prompt):
    if prompt[-1] != " ":
        prompt += " "

    ret = raw_input(prompt).strip()
    if len(ret):
        ret = ret[0]

    return ret.lower() == "y"

def _run_filter(filter_func, filter_args, good_users, problem_users):
    """
    Runs the filter and affects the contents of good_users and problem_users
    """
    filter_results = filter_func(*filter_args)
    good_users.difference_update(filter_results)
    problem_users.update(filter_results)

def _filter_log_duplicates(users_entries, log_entries):
    """
    returns the users that fail this filter
    meaning they will NOT be created
    """
    problem_users = set()

    users_account_names = set([entry["account_name"] for entry in users_entries])
    unique_log_names = set()
    for log_entry in log_entries:
        if log_entry["account_name"] in users_account_names:
            if log_entry["account_name"] in unique_log_names:
                print "Duplicate entry detected in approved.log file. Possible multiple approval."
                if not prompt_returns_yes("Approve duplicate %s?" % log_entry["account_name"]):
                    print "Adding to problem users"
                    problem_users.add(log_entry["account_name"])
            else:
                unique_log_names.add(log_entry["account_name"])
    return problem_users

def _filter_duplicates(key, approved_users, error_str, good_users, unique_function = lambda x: x):
    problem_users = set()
    unique_values = dict()
    for user in good_users:
        entry = approved_users[user]
        if not entry[key]:
            print "Skipping %s" % user
            continue
        unique_of_entry = unique_function(entry[key])
        if unique_values.has_key(unique_of_entry) and unique_of_entry !="(null)":
            print "%s: %s for %s" % \
                (error_str, unique_of_entry, user)
            old_value = unique_values[unique_of_entry]
            if not prompt_returns_yes("Approve %s?" % user):
                print "Adding %s to problem users\n" % user
                problem_users.add(user)
            if not prompt_returns_yes("Approve the first of the duplicates, %s?" % old_value):
                print "Adding %s to problem users\n" % old_value
                problem_users.add(old_value)
        else:
            unique_values[unique_of_entry] = user
    return problem_users

def _filter_real_name_duplicates(approved_users, good_users):
    return _filter_duplicates("personal_owner", approved_users, "Duplicate real name for account detected",
        good_users, lambda real_name: real_name.strip().lower())

def _filter_calnet_uid_duplicates(approved_users, good_users):
    return _filter_duplicates("calnet_uid", approved_users, "Duplicate CalNet UID detected",
        good_users)

def _filter_email_duplicates(approved_users, good_users):
    return _filter_duplicates("email", approved_users, "Duplicate email address detected",
        good_users)

def _filter_ocf_duplicates(approved_users, good_users, options, conflict_uid_lower_bound):
    problem_users = set()
    base_dn = "ou=people,dc=ocf,dc=berkeley,dc=edu"
    retrieve_attrs = ["uidNumber", "cn"]

    for user in good_users:
        entry = approved_users[user]

        if entry["personal_owner"]:
            name = entry["personal_owner"]
        elif entry["group_owner"]:
            name = entry["group_owner"]
        else:
            raise Exception("Unable to discern name for requested acccount %s" % entry["account_name"])

        search_filter = "cn=*{}*".format(name).replace(" ", "*")
        results = options.ocf_ldap.search_st(base_dn, ldap.SCOPE_SUBTREE,
                                             search_filter, retrieve_attrs)
        if results:
            conflicting_entry = results[0][1]
            conflicting_uid_number = conflicting_entry["uidNumber"][0]
            if conflicting_uid_number >= conflict_uid_lower_bound:
                print "Possible existing account [req-fullname, req-username, coll-uid, coll-fullname]: %s, %s, %s, %s" % (name, user, conflicting_uid_number, conflicting_entry["cn"][0])
                if not prompt_returns_yes("Approve?"):
                    problem_users.add(user)

    return problem_users

def _filter_registration_status(approved_users, good_users, options):
    problem_users = set()
    base_dn = "dc=berkeley,dc=edu"
    retrieve_attrs = ["berkeleyEduAffiliations", "displayName"]

    for user in good_users:
        entry = approved_users[user]
        if not entry["personal_owner"]:
            print "Skipping CalNet registration check for group account",
            print entry["account_name"]
            continue

        search_filter = "uid={}".format(["calnet_uid"])

        print "Looking up CalNet entry for {} ({})".format(entry["calnet_uid"],
                                                           entry["account_name"])

        results = options.calnet_ldap.search_st(base_dn, ldap.SCOPE_SUBTREE,
                                                search_filter, retrieve_attrs)
        if not results:
            print "No CalNet entry found"

            if not prompt_returns_yes("Approve %s?" % entry["account_name"]):
                problem_users.add(user)
        else:
            result = results[0][1]
            if "STUDENT-TYPE-REGISTERED" not in result["berkeleyEduAffiliations"]:
                print "{} ({}) requested {}, but is not a registered student: {}".format(
                    result["displayName"][0],
                    entry["personal_owner"],
                    entry["account_name"],
                    result["berkeleyEduAffiliations"])

                if not prompt_returns_yes("Approve?"):
                    problem_users.add(user)

    return problem_users

def _filter_usernames_manually(approved_users, good_users):
    problem_users = set()
    for user in good_users:
        entry = approved_users[user]
        account_name = entry["account_name"]
        real_name = entry["personal_owner"] or entry["group_owner"]
        if not prompt_returns_yes("Approve %s for %s?" % (account_name, real_name)):
            print "Adding %s to problem users" % user
            problem_users.add(user)
        print
    return problem_users

def filter_accounts(users, options):
    """
    Filter accounts into auto-accepted, needs-staff-approval, and rejected.
    """

    approved_users = {} # dict from account name => users_entry
    accepted = set() # set of account_names (strings)
    needs_staff_approval = set()
    rejected = set()

    print "Getting current max uid ..."
    max_uid = _get_max_uid_number(options.ocf_ldap_url)
    print "UIDs for new users will start at {}".format(max_uid + 1)

    print "Parsing log entries from {} ...".format(options.log_file)
    with open(options.log_file) as f:
        log_entries = get_log_entries(f)
    print

    good_users = set([users_entry["account_name"] for users_entry in users])

    print "Checking approved.log for duplicate requests"
    _run_filter(_filter_log_duplicates, [users_entries, log_entries], good_users, problem_users)
    print

    print "Generating approved_users dictionary of account_name => approved.users entry"
    approved_users = dict((user["account_name"], user) for user in users_entries)
    print

    print "Checking for real name duplicates"
    _run_filter(_filter_real_name_duplicates, [approved_users, good_users], good_users, problem_users)
    print

    print "Checking for CalNet UID duplicates"
    _run_filter(_filter_calnet_uid_duplicates, [approved_users, good_users], good_users, problem_users)
    print

    print "Checking for email address duplicates"
    _run_filter(_filter_email_duplicates, [approved_users, good_users], good_users, problem_users)
    print

    print "Checking for OCF existing accounts"
    _run_filter(_filter_ocf_duplicates, [approved_users, good_users, options, \
        options.conflict_uid_lower_bound], good_users, problem_users)
    print

    print "Checking CalNet for registration status"
    _run_filter(_filter_registration_status, [approved_users, good_users, options],
        good_users, problem_users)
    print

    print "Checking requested usernames"
    _run_filter(_filter_usernames_manually, [approved_users, good_users], good_users, problem_users)
    print

    # done with filtering
    # now we write to file

    problem_users_entries = [approved_users[user] for user in problem_users]
    good_users_entries = []
    # need to assign uid to new users
    # as well as passwords
    next_uid = max_uid + 1
    for user in good_users:
        entry = approved_users[user]
        entry["uid_number"] = next_uid
        good_users_entries.append(entry)
        next_uid += 1

    print "Writing tmp/approved.users.bad"
    with open("tmp/approved.users.bad", "a") as f:
        write_users(f, problem_users_entries)
    print

    print "Writing tmp/approved.users.good"
    with open("tmp/approved.users.good", "a") as f:
        write_users(f, good_users_entries)
    print
