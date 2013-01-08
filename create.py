"""
Let there be light.

User creation tool.
"""

import ldap
import sys
import argparse

ACCOUNT_CREATED_LETTER="txt/acct.created.letter"

def _associate_calnet(username):
    pass

def _check_username(username):
    pass

def _forward_add(username):
    firstchar = username[0]
    firsttwochar = username[:1]
    pass

def _homedir_add(username):
    firstchar = username[0]
    firsttwochar = username[:1]
    pass

def _kerberos_add(username):
    pass

def _sendemail(username):
    pass

def _email_problems():
    pass

def _finish_account_creation():
    pass

def _get_max_uid_number():
    l = ldap.initialize("ldaps://ldap-master.ocf.berkeley.edu")
    l.simple_bind_s('','')
    ldap_entries = l.search_st("ou=People,dc=OCF,dc=Berkeley,dc=EDU",
                               ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
    uid_numbers = [max([int(num) for num in entry[1]["uidNumber"]])
                   for entry in ldap_entries]
    max_uid_number = max(uid_numbers)
    return max_uid_number

def _process_group(username, group_name, email, forward, password, university_id):
    print "group", group_name

def _process_user(username, real_name, email, forward, password, university_id):
    print "user", username

def main(args):
    """
    Process a file contain a list of user accounts to create.
    """

    parser = argparse.ArgumentParser(description = 'Process and create user accounts.')
    parser.add_argument('approved', type = file, nargs = '+',
                        help = 'user accounts awaiting creation')

    parsed = parser.parse_args()

    # Process all of the requested accounts
    for f in parsed.approved:
        for line in f:
            username, real_name, group_name, email, forward, \
              group, password, key, university_id = line.split(":")

            if bool(int(group)):
                _process_group(username, group_name, email, forward,
                               password, university_id)
            else:
                _process_user(username, real_name, email, forward,
                              password, university_id)

    # Dump the new account requests

    # Clear the input files

if __name__ == "__main__":
    main(sys.argv)
