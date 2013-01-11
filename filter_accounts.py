#!/usr/bin/env python

from subprocess import Popen, PIPE
import ldap
import pwd, grp
import os
import sys
import optparse
import shlex

def _create_parser():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--usersfile", dest="users_file",
        help="Input file of approved users", default="/opt/adm/approved.users")
    parser.add_option("-l", "--logfile", dest="log_file",
        help="Input file of approved log", default="/opt/adm/approved.log")
    parser.add_option("-c", "--calnetldap", dest="calnet_ldap_url",
        help="Url of CalNet's LDAP", default="ldap://169.229.218.90")
    parser.add_option("-o", "--ocfldap", dest="ocf_ldap_url",
        help="Url of OCF's LDAP", default="ldaps://ldap.ocf.berkeley.edu")
    parser.add_option("-b", "--uidlowerbound", dest="conflict_uid_lower_bound",
        help="Lower bound for OCF name collision detection", default=16000)
    return parser

def _get_max_uid_number(connection):
    entries = connection.search_st("ou=People,dc=OCF,dc=Berkeley,dc=EDU",
                                   ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
    uid_numbers = (int(num)
                   for num in entry[1]["uidNumber"]
                   for entry in entries)

    return max(uid_numbers)

def _parse_file(filename, parser_function):
    entries = []
    with open(filename, "r") as f:
        data = f.read().strip()
        lines = data.split("\n")
        for (line_number, line) in zip(range(1, len(lines) + 1), lines):
            if len(line.strip()) == 0:
                # ignore empty lines
                continue
            try:
                parsed_entry = parser_function(line)
            except Exception as e:
                print "Error parsing line %s: %s" % (line_number, line)
                raise e
            entries.append(parser_function(line))
    return entries

def _write_file(filename, template_function, list_of_data):
    with open(filename, "w") as f:
        for data in list_of_data:
            f.write(template_function(data))

def _write_approved_users_file(filename, users_list):
    def _write_approved_users_line(user):
        return "%s:%s:%s:%s:%s:%s:%s:%s:%s\n" % \
            (user["account_name"],
            user["personal_owner"] if user["personal_owner"] else "(null)",
            user["group_owner"] if user["group_owner"] else "(null)",
            user["email"],
            "1" if user["forward_email"] else "0",
            "1" if user["is_group_account"] else "0",
            user["heimdal_secret"],
            user["heimdal_key"],
            user["calnet_uid"])
    return _write_file(filename, _write_approved_users_line, users_list)

def _write_ldif_file(filename, users_list):
    def _write_ldif_line(user):
        return_dict = {
    "username": user["account_name"],
    "realname": user["personal_owner"] or user["group_owner"],
    "uidnumber": user["uid_number"],
    "firstletter": user["account_name"][0],
    "twoletters": user["account_name"][0:2]
    }
        if user.has_key("calnet_uid") and user["calnet_uid"].isdigit():
            return_dict["calnet_entry"] = "\ncalNetuid: %s" % user["calnet_uid"]
        else:
            return_dict["calnet_entry"] = ""


        return """
dn: uid=%(username)s,ou=People,dc=OCF,dc=Berkeley,dc=EDU
objectClass: ocfAccount
objectClass: account
objectClass: posixAccount
cn: %(realname)s
uid: %(username)s
uidNumber: %(uidnumber)s
gidNumber: 20
homeDirectory: /home/%(firstletter)s/%(twoletters)s/%(username)s
loginShell: /bin/bash
gecos: %(realname)s %(calnet_entry)s

""" % return_dict
    return _write_file(filename, _write_ldif_line, users_list)

def _write_bat_file(filename, users_list):
    def _write_bat_line(user):
        first_name = ""
        last_name = ""
        full_name = user["personal_owner"] or user["group_owner"]
        if user["personal_owner"]:
            split_full_name = full_name.split(" ")
            first_name = split_full_name[0]
            last_name = split_full_name[-1]
        else:
            first_name = full_name
            last_name = full_name
        return "dsadd user \"CN=%(username)s,OU=people,DC=lab,DC=ocf,DC=berkeley,DC=edu\" -fn \"%(firstname)s\" -ln \"%(lastname)s\" -display \"%(realname)s\" -pwd \"%(password)s\" -profile \\BIOHAZARD\RoamingProfiles\$username$ -canchpwd yes -mustchpwd no -pwdneverexpires yes\n" % \
            {"username": user["account_name"],
            "firstname": first_name,
            "lastname": last_name,
            "realname": full_name,
            "password": user["password"]}

    return _write_file(filename, _write_bat_line, users_list)

def _write_heimdal_dump_file(filename, users_list):
    def _write_heimdal_dump_line(user):
        return "%(account_name)s %(password)s\n" % user

    return _write_file(filename, _write_heimdal_dump_line, users_list)

def prompt_returns_yes(prompt):
    if prompt[-1] != " ":
        prompt = "%s " % prompt
    ret = raw_input(prompt).strip()
    if len(ret):
        ret = ret[0]

    return ret.lower() == "y"

def run_filter(filter_func, filter_args, good_users, problem_users):
    """
    Runs the filter and affects the contents of good_users and problem_users
    """
    filter_results = filter_func(*filter_args)
    good_users.difference_update(filter_results)
    problem_users.update(filter_results)

def filter_log_duplicates(users_entries, log_entries):
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

def filter_duplicates(key, approved_users, error_str, good_users, unique_function = lambda x: x):
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

def filter_real_name_duplicates(approved_users, good_users):
    return filter_duplicates("personal_owner", approved_users, "Duplicate real name for account detected",
        good_users, lambda real_name: real_name.strip().lower())

def filter_calnet_uid_duplicates(approved_users, good_users):
    return filter_duplicates("calnet_uid", approved_users, "Duplicate CalNet UID detected",
        good_users)

def filter_email_duplicates(approved_users, good_users):
    return filter_duplicates("email", approved_users, "Duplicate email address detected",
        good_users)

def filter_ocf_duplicates(approved_users, good_users, ocf_ldap_url, conflict_uid_lower_bound):
    try:
        l = ldap.initialize(ocf_ldap_url)
        l.protocol_version = ldap.VERSION3
    except ldap.LDAPError as e:
        print e

    problem_users = set()
    baseDN = "ou=people,dc=ocf,dc=berkeley,dc=edu"
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttrs = ["uidNumber", "cn"]

    for user in good_users:
        entry = approved_users[user]

        if entry["personal_owner"]:
            name = entry["personal_owner"]
        elif entry["group_owner"]:
            name = entry["group_owner"]
        else:
            raise Exception("Unable to discern name for requested acccount %s" % entry["account_name"])

        searchFilter = "cn=%s" % (" %s " % name).replace(" ", "*")
        try:
            ldap_results = l.search_st(baseDN, searchScope, searchFilter, retrieveAttrs)
            if len(ldap_results) != 0:
                conflicting_entry = ldap_results[0][1]
                conflicting_uid_number = conflicting_entry["uidNumber"][0]
                if conflicting_uid_number >= conflict_uid_lower_bound:
                    print "Possible existing account [req-fullname, req-username, coll-uid, coll-fullname]: %s, %s, %s, %s" % (name, user, conflicting_uid_number, conflicting_entry["cn"][0])
                    if not prompt_returns_yes("Approve?"):
                        problem_users.add(user)
        except ldap.LDAPError as e:
            print e

    return problem_users

def filter_registration_status(approved_users, good_users, calnet_ldap_url):
    try:
        l = ldap.initialize(calnet_ldap_url)
        l.protocol_version = ldap.VERSION3
    except ldap.LDAPError as e:
        print e

    problem_users = set()
    baseDN = "dc=berkeley,dc=edu"
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttrs = ["berkeleyEduAffiliations", "displayName"]

    for user in good_users:
        entry = approved_users[user]
        if not entry["personal_owner"]:
            print "Skipping CalNet registration check for group account %s" % entry["account_name"]
            continue

        searchFilter = "uid=%s" % entry["calnet_uid"]

        try:
            ldap_results = l.search_st(baseDN, searchScope, searchFilter, retrieveAttrs)
            if len(ldap_results) == 0:
                print "No CalNet entry found for %s (%s)" % (entry["calnet_uid"], entry["account_name"])
                if not prompt_returns_yes("Approve %s?" % entry["account_name"]):
                    problem_users.add(user)
            else:
                result = ldap_results[0][1]
                if "STUDENT-TYPE-REGISTERED" not in result["berkeleyEduAffiliations"]:
                    print "%s (%s) requested %s, but is not a registered student: %s" % \
                        (result["displayName"][0],
                        entry["personal_owner"],
                        entry["account_name"],
                        result["berkeleyEduAffiliations"])
                    if not prompt_returns_yes("Approve?"):
                        problem_users.add(user)
        except ldap.LDAPError as e:
            print e
    return problem_users

def filter_usernames_manually(approved_users, good_users):
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

    parser = _create_parser()
    (options, args) = parser.parse_args()

    approved_users = {} # dict from account name => users_entry
    good_users = set() # set of account_names (strings)
    problem_users = set()

    print "Getting current max uid ..."
    max_uid = _get_max_uid_number(options.ocf_ldap_url)
    print "UIDs for new users will start at %s" % (max_uid + 1)

    print "Parsing %s file as approved.log ..." % options.log_file
    log_entries = _parse_log_file(options.log_file)
    print

    print "Parsing %s file as approved.users ..." % options.users_file
    users_entries = _parse_users_file(options.users_file)
    print

    good_users = set([users_entry["account_name"] for users_entry in users_entries])

    print "Checking approved.log for duplicate requests"
    run_filter(filter_log_duplicates, [users_entries, log_entries], good_users, problem_users)
    print

    print "Generating approved_users dictionary of account_name => approved.users entry"
    for users_entry in users_entries:
        approved_users[users_entry["account_name"]] = users_entry
    print

    print "Checking for real name duplicates"
    run_filter(filter_real_name_duplicates, [approved_users, good_users], good_users, problem_users)
    print

    print "Checking for CalNet UID duplicates"
    run_filter(filter_calnet_uid_duplicates, [approved_users, good_users], good_users, problem_users)
    print

    print "Checking for email address duplicates"
    run_filter(filter_email_duplicates, [approved_users, good_users], good_users, problem_users)
    print

    print "Checking for OCF existing accounts"
    run_filter(filter_ocf_duplicates, [approved_users, good_users, options.ocf_ldap_url, \
        options.conflict_uid_lower_bound], good_users, problem_users)
    print

    print "Checking CalNet for registration status"
    run_filter(filter_registration_status, [approved_users, good_users, options.calnet_ldap_url],
        good_users, problem_users)
    print

    print "Checking requested usernames"
    run_filter(filter_usernames_manually, [approved_users, good_users], good_users, problem_users)
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
    _write_approved_users_file("tmp/approved.users.bad", problem_users_entries)
    print

    print "Writing tmp/approved.users.good"
    _write_approved_users_file("tmp/approved.users.good", good_users_entries)
    print

    print "Writing tmp/addusers.ldif"
    _write_ldif_file("tmp/addusers.ldif", good_users_entries)
    print

    print "Writing tmp/addusers.bat"
    _write_bat_file("tmp/addusers.bat", good_users_entries)
    print

    print "Writing tmp/heimdal.dump"
    _write_heimdal_dump_file("tmp/heimdal.dump", good_users_entries)
    print
