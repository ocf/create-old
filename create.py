"""
Let there be light.

User creation tool.
"""

# Dependencies:
# python2.7
# python-ldap
# pycrypto

import sys
import os
import shutil
import argparse
from datetime import datetime
from pwd import getpwnam
from grp import getgrnam

# Email
import smtplib
from email.mime.text import MIMEText

# LDAP
import ldap

# Password decryption
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

ACCOUNT_CREATED_LETTER = os.path.join(os.path.dirname(__file__),
                                      "txt", "acct.created.letter")

LDAP_CON = None
RSA_CIPHER = None

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
        dest = os.path.join(home, name)
        shutil.copy2(os.path.join(os.path.dirname(__file__), rc, name), home)
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

def _process_group(username, group_name, email, forward, password, university_id):
    print "group", group_name

def _process_user(username, real_name, email, forward, password, university_id):
    print "user", username

def _decrypt_password(password, priv_key):
    # Use an asymmetric encryption algorithm to allow the keys to be stored on disk
    # Generate the public / private keys with the following code:
    # >>> from Crypto.PublicKey import RSA
    # >>> key = RSA.generate(2048)
    # >>> open("private.pem", "w").write(key.exportKey())
    # >>> open("public.pem", "w").write(key.publickey().exportKey())

    global RSA_CIPHER

    if RSA_CIPHER is None:
        key = RSA.importKey(open(priv_key).read())
        RSA_CIPHER = PKCS1_OAEP.new(key)

    return RSA_CIPHER.decrypt(password)

def _create_parser():
    parser = argparse.ArgumentParser(description = 'Process and create user accounts.')
    parser.add_option("-u", "--usersfile", dest = "users_file",
                      default = "/opt/adm/approved.users",
                      help = "Input file of approved users")
    parser.add_option("-l", "--logfile", dest = "log_file",
                      default = "/opt/adm/approved.log",
                      help = "Input file of approved log")
    parser.add_option("-p", "--priv-key", dest = "rsa_priv_key",
                      default = "/opt/adm/pass_private.pem",
                      help = "Private key to decrypt user passwords")
    parser.add_option("-c", "--calnetldap", dest = "calnet_ldap_url",
                      default = "ldap://169.229.218.90",
                      help = "Url of CalNet's LDAP")
    parser.add_option("-o", "--ocfldap", dest = "ocf_ldap_url",
                      default = "ldaps://ldap.ocf.berkeley.edu",
                      help = "Url of OCF's LDAP")
    parser.add_option("-b", "--uidlowerbound", dest = "conflict_uid_lower_bound",
                      default = 16000,
                      help = "Lower bound for OCF name collision detection")
    return parser

def main(args):
    """
    Process a file contain a list of user accounts to create.
    """

    parsed = _create_parser().parse_args()

    # Connect to LDAP
    global LDAP_CON
    LDAP_CON = ldap.initialize(parser.ldap)
    LDAP_CON.simple_bind_s('','')

    # Process all of the requested accounts
    for f in parsed.approved:
        for line in f:
            username, real_name, group_name, email, forward, \
              group, password, key, university_id = line.split(":")

            password = base64.b64encode(_decrypt_password(password, parser.rsa_priv_key))

            # Filter into auto-accepted, needs-staff-approval, and rejected
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
