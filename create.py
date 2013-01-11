"""
Let there be light.

User creation tool.
"""

# Dependencies:
# python2.7
# python-ldap
# pycrypto

import argparse
import os
import shutil
import sys
from datetime import datetime
from grp import getgrnam
from pwd import getpwnam

# Email
import smtplib
from email.mime.text import MIMEText

import filter_accounts
from utils import get_users, LDAPAction, decrypt_password, fancy_open

ACCOUNT_CREATED_LETTER = os.path.join(os.path.dirname(__file__),
                                      "txt", "acct.created.letter")

MID_APPROVAL = [] # A list of accounts in the mid stage of approval, to prevent dups

def _associate_calnet(username):
    pass

def _check_username(username):
    pass

def _homedir(username):
    """
    Returns the user's home directory: "/home/u/us/username".
    """
    return os.path.sep + os.path.join("home", username[0], username[:2], username)

def _httpdir(username):
    """
    Returns the user's http directory: "/services/http/users/u/username".
    """
    return os.path.sep + os.path.join("services", "http", "users", username[0], username)

def _ldap_add(user, connection, shell = "/bin/bash"):
    dn = "uid={},ou=People,dc=OCF,dc=Berkeley,dc=EDU".format(user["username"])
    attrs = {
        "objectClass": "ocfAccount",
        "objectClass": "account",
        "objectClass": "posixAccount",
        "cn": user["real_name"],
        "uid": user["username"],
        "uidNumber": user["university_id"],
        "gidNumber": getgrnam("ocf").gr_gid,
        "homeDirectory": _homedir(user["username"]),
        "loginShell": shell,
        "gecos": user["real_name"]
    }

    if "calnet_uid" in user and user["calnet_uid"].isdigit():
        attrs["calNetuid"] = user["calnet_uid"] # str() this?

    # Enter it into LDAP
    ldif = ldap.modlist.addModlist(attrs)
    connection.add_s(dn, ldif)

def _forward_add(user):
    if user["forward"]:
        forward = os.path.join(_homedir(user["username"]), ".forward")

        with open(forward, "w") as f:
            f.write(user["email"] + "\n")

        os.chown(forward, getpwnam(user["username"]).pwd_uid, getgrnam("ocf").gr_gid)

def _homedir_add(user):
    home = _homedir(user["username"])
    http = _httpdir(user["username"])

    os.makedirs(home)
    os.makedirs(http)

    os.chown(home, getpwnam(user["username"]).pw_uid, getgrnam("ocf").gr_gid)
    os.chown(http, getpwnam(user["username"]).pw_uid, getgrnam("ocf").gr_gid)

    os.chmod(home, 0700)
    os.chmod(http, 0000)

    for name in [".cshrc", ".bashrc", ".bash_profile", ".bash_logout"]:
        shutil.copy2(os.path.join(os.path.dirname(__file__), rc, name), home)

        dest = os.path.join(home, name)
        os.chown(dest, getpwnam(user["username"]).pw_uid, getgrnam("ocf").gr_gid)
        os.chmod(dest, 0600)

def _kerberos_add(username):
    pass

def _sendemails(users):
    """
    Notify users and staff that accounts were created.
    """

    created_text = open(ACCOUNT_CREATED_LETTER).read()
    s = smtplib.SMTP("localhost")
    me = "OCF staff <help@ocf.berkeley.edu>"
    staff = "staff@ocf.berkeley.edu"

    for user in users:
        msg = MIMEText(CREATED_TXT.format(username = user["username"]))
        msg["Subject"] = "OCF account created"
        msg["From"] = me
        msg["To"] = user["email"]

        s.sendmail(me, [user["email"]], msg.as_string())

    # Notify staff of all the created accounts
    body = "Accounts created on {}:\n".format(datetime.now())

    for user in users:
        body += "{}: {}\n".format(user["username"], user["real_name"])

    msg = MIMEText(body)
    msg["Subject"] = "Created OCF accounts"
    msg["From"] = me
    msg["To"] = staff

    s.sendmail(me, [staff], msg.as_string())

    s.quit()

def _email_problems():
    pass

def _finish_account_creation(src):
    now = datetime.now().strftime("%Y-%m-%d")
    directory, name = os.path.split(source)

    dest = os.path.join(directory, "..", "oldapprovedusers", "{}.{}".format(name, now))
    shutil.move(src, dest)

    # All this chown / chmod'ing necessary? Aren't we guaranteed to be running as root?
    os.chown(dest, getpwnam("root").pw_uid, getgrnam("root").gr_gid)
    os.chmod(dest, 0600)

    with open(src, "a"):
        pass

    os.chown(src, getpwnam("root").pw_uid, getgrnam("root").gr_gid)
    os.chmod(src, 0600)

def _get_max_uid_number():
    entries = LDAP_CON.search_st("ou=People,dc=OCF,dc=Berkeley,dc=EDU",
                                 ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
    uid_numbers = (int(num)
                   for num in entry[1]["uidNumber"]
                   for entry in entries)

    return max(uid_numbers)

def _process_group(username, group_name, email, forward, password, university_id,
                   options):
    print "group", group_name

def _process_user(username, real_name, email, forward, password, university_id,
                  options):
    """
    Filter into auto-accepted, needs-staff-approval, and rejected.
    """

    print "user", username

def _create_parser():
    parser = argparse.ArgumentParser(description = 'Process and create user accounts.')
    parser.add_argument("-u", "--usersfile", dest = "users_file",
                        default = "/opt/adm/approved.users",
                        help = "Input file of approved users")
    parser.add_argument("-m", "--midapprove", dest = "mid_approve",
                        default = "/opt/adm/mid_approved.users",
                        help = "Input file of users in mid stage of approval")
    parser.add_argument("-s", "--staffapprove", dest = "staff_approve",
                        default = "/opt/adm/staff_approve.users",
                        help = "Output file for users requiring manual staff approval")
    parser.add_argument("-l", "--logfile", dest = "log_file",
                        default = "/opt/adm/approved.log",
                        help = "Input file of approved log")
    parser.add_argument("-p", "--priv-key", dest = "rsa_priv_key",
                        default = "/opt/adm/pass_private.pem",
                        help = "Private key to decrypt user passwords")
    parser.add_argument("-c", "--calnetldap", dest = "calnet_ldap_url",
                        default = "ldap://169.229.218.90",
                        action = LDAPAction,
                        help = "Url of CalNet's LDAP")
    parser.add_argument("-o", "--ocfldap", dest = "ocf_ldap_url",
                        action = LDAPAction,
                        default = "ldaps://ldap.ocf.berkeley.edu",
                        help = "Url of OCF's LDAP")
    parser.add_argument("-b", "--uidlowerbound", dest = "conflict_uid_lower_bound",
                        default = 16000,
                        help = "Lower bound for OCF name collision detection")
    return parser

def main(args):
    """
    Process a file contain a list of user accounts to create.
    """

    options = _create_parser().parse_args()

    # Process the users in the mid stage of approval first
    with fancy_open(options.mid_approve, lock = True,
                    delete = True, pass_missing = True) as f:
        for user in get_users(f, options):
            if user["group"]:
                _finalize_group(user, options)
            else:
                _finalize_user(user, options)

    # Process all of the recently requested accounts
    with fancy_open(options.users_file, lock = True,
                    delete = True, pass_missing = True) as f:
        for user in get_users(f, options):
            if user["group"]:
                _process_group(username, group_name, email, forward,
                               password, university_id, options)
            else:
                _process_user(username, real_name, email, forward,
                              password, university_id, options)

if __name__ == "__main__":
    main(sys.argv)
