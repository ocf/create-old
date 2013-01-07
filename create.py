"""
Let there be light.

User creation tool.
"""

import ldap
import sys

ACCOUNT_CREATED_LETTER="txt/acct.created.letter"

def _associate_calnet(username):
    pass

def _check_username(username):
    pass

def _forward_add(username):
    pass

def _homedir_add(username):
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
	ldap_entries = l.search_st("ou=People,dc=OCF,dc=Berkeley,dc=EDU", ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
	uid_numbers = [max([int(num) for num in entry[1]["uidNumber"]]) for entry in ldap_entries]
	max_uid_number = max(uid_numbers)
	return max_uid_number

def main(args):
    """
    Process a file contain a list of user accounts to create.
    """

    # Make it of the format create.py <command> <args>?
    pass

if __name__ == "__main__":
    main(sys.argv)
