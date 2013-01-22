"""
Code to create the user accounts on the system.
"""

from datetime import datetime
from email.mime.text import MIMEText
from getpass import getuser
from grp import getgrnam
import os
import pexpect
from pwd import getpwnam
from socket import gethostname
from subprocess import PIPE, Popen, check_call
from time import asctime

import ldap
import ldap.modlist

from ocf import home_dir, http_dir, OCF_DN

ACCOUNT_CREATED_LETTER = \
  os.path.join(os.path.dirname(__file__), "txt", "acct.created.letter")

def _ldap_add(users, connection, shell = "/bin/bash"):
    for user in users:
        dn = "uid={0},{1}".format(user["account_name"], OCF_DN)
        attrs = {
            "objectClass": "ocfAccount",
            "objectClass": "account",
            "objectClass": "posixAccount",
            "cn": user["owner"],
            "uid": user["account_name"],
            "uidNumber": user["uid_number"],
            "gidNumber": str(getgrnam("ocf").gr_gid),
            "homeDirectory": home_dir(user["account_name"]),
            "loginShell": shell,
            "gecos": user["owner"],
        }

        if "calnet_uid" in user:
            attrs["calNetuid"] = str(user["calnet_uid"])
        elif not user["is_group"]:
            raise KeyError("User does not have calnet uid set")

        # Enter it into LDAP
        ldif = ldap.modlist.addModlist(attrs)
        connection.add_s(dn, ldif)

    # Invalidate the local cache so we can chown their files later
    check_call(["nscd", "-i", "passwd"])

def _homedir_add(user):
    home = home_dir(user["account_name"])
    http = http_dir(user["account_name"])

    os.makedirs(home)
    os.makedirs(http)

    os.chown(home, getpwnam(user["account_name"]).pw_uid, getgrnam("ocf").gr_gid)
    os.chown(http, getpwnam(user["account_name"]).pw_uid, getgrnam("ocf").gr_gid)

    os.chmod(home, 0700)
    os.chmod(http, 0000)

    for name in [".cshrc", ".bashrc", ".bash_profile", ".bash_logout"]:
        shutil.copy2(os.path.join(os.path.dirname(__file__), rc, name), home)

        dest = os.path.join(home, name)
        os.chown(dest, getpwnam(user["account_name"]).pw_uid, getgrnam("ocf").gr_gid)
        os.chmod(dest, 0600)

def _forward_add(user):
    if user["forward"]:
        forward = os.path.join(home_dir(user["account_name"]), ".forward")

        with open(forward, "w") as f:
            f.write(user["email"] + "\n")

        os.chown(forward, getpwnam(user["account_name"]).pwd_uid, getgrnam("ocf").gr_gid)

def _kerberos_add(users, options):
    kadmin = pexpect.spawn("kadmin", ["-p", "{0}/admin".format(options.admin_user)])
    kadmin.expect("kdamin> ")

    for user in users:
        # We don't have a decent kerberos python module for administration commands
        user_passord = \
          _decrypt_password(base64.b64decode(user["password"]), options.rsa_priv_key).decode()

        # Call the add command
        kadmin.sendline("add --password={0} --use-defaults {1}\n".format(user_password, user["account_name"]))

        i = 0

        while i == 0:
            i = kadmin.expect(
                ["{0}/admin@OCF.BERKELEY.EDU's Password:".format(options.admin_user),
                 "kadmin> ",
                 "kadmin: [^\n]*"])

            if i == 0:
                kadmin.sendline(options.admin_password)
            elif i == 2:
                print kadmin.match.group(0)
                kadmin.expect("kadmin> ")

    kadmin.sendline("exit")
    kadmin.expect(pexpect.EOF)

def _send_finalize_emails(users, options,
                          me = "OCF staff <staff@ocf.berkeley.edu>",
                          reply_to = "help@ocf.berkeley.edu",
                          staff = "staff@ocf.berkeley.edu"):
    """
    Notify users and staff that accounts were created.
    """

    if users and options.email:
        created_text = open(ACCOUNT_CREATED_LETTER).read()

        for user in users:
            msg = MIMEText(created_text.format(account_name = user["account_name"]))
            msg["Subject"] = "OCF account created"
            msg["From"] = me
            msg["Reply-To"] = reply_to
            msg["To"] = user["email"]

            s = Popen(["sendmail", "-t"], stdin = PIPE)
            s.communicate(msg.as_string())

        # Notify staff of all the created accounts
        body = "Accounts created on {0}:\n".format(datetime.now())

        for user in users:
            body += "{0}: {1}\n".format(user["account_name"], user["owner"])

        msg = MIMEText(body)
        msg["Subject"] = "Created OCF accounts"
        msg["From"] = me
        msg["To"] = staff

        s = Popen(["sendmail", "-t"], stdin = PIPE)
        s.communicate(msg.as_string())

def _get_max_uid_number(connection):
    entries = connection.search_st(OCF_DN, ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
    uid_numbers = (int(num)
                   for entry in entries
                   for num in entry[1]["uidNumber"])

    return max(uid_numbers)

def finalize_accounts(users, options):
    users = list(users)

    if users:
        # Need to assign uid to new users
        print "Getting current max uid ..."
        uid_start = _get_max_uid_number(options.ocf_ldap) + 1
        print "UIDs for new users will start at {0}".format(uid_start)

        for uid, user in enumerate(users, start = uid_start):
            user["uid_number"] = uid

        for user in users:
            _finalize_account(user, options)

        _send_finalize_emails(users, options)

def _log_created(user, options):
    with fancy_open(options.log_file, "a", lock = True) as f:
        sections = [user["account_name"], user["owner"], user["calnet_uid"],
                    getuser(), gethostname(), 1, user["is_group"], asctime()]

        f.write(":".join([str(i) for i in sections]) + "\n")

def _finalize_account(user, options):
    """
    Create a new account on the system.
    """

    print "Creating new account, {0}, for {1}".format(user["account_name"], user["owner"])

    _ldap_add([user], options.ocf_ldap)
    _homedir_add(user)
    _forward_add(user)
    _kerberos_add([user], options)

    _log_created(user, options)
