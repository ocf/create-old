"""
Code to create the user accounts on the system.
"""

from datetime import datetime
from email.mime.text import MIMEText
from grp import getgrnam
import ldap
import os
from pwd import getpwnam
from subprocess import PIPE, Popen

ACCOUNT_CREATED_LETTER = \
  os.path.join(os.path.dirname(__file__), "txt", "acct.created.letter")

def _homedir(account_name):
    """
    Returns the user's home directory: "/home/u/us/account_name".
    """
    return os.path.sep + \
      os.path.join("home", account_name[0], account_name[:2], account_name)

def _httpdir(account_name):
    """
    Returns the user's http directory: "/services/http/users/u/account_name".
    """
    return os.path.sep + \
      os.path.join("services", "http", "users", account_name[0], account_name)

def _ldap_add(user, connection, shell = "/bin/bash"):
    dn = "uid={},ou=People,dc=OCF,dc=Berkeley,dc=EDU".format(user["account_name"])
    attrs = {
        "objectClass": "ocfAccount",
        "objectClass": "account",
        "objectClass": "posixAccount",
        "cn": user["personal_owner"],
        "uid": user["account_name"],
        "uidNumber": user["calnet_uid"],
        "gidNumber": getgrnam("ocf").gr_gid,
        "homeDirectory": _homedir(user["account_name"]),
        "loginShell": shell,
        "gecos": user["personal_owner"]
    }

    if "calnet_uid" in user and user["calnet_uid"].isdigit():
        attrs["calNetuid"] = user["calnet_uid"] # str() this?

    # Enter it into LDAP
    ldif = ldap.modlist.addModlist(attrs)
    connection.add_s(dn, ldif)

def _homedir_add(user):
    home = _homedir(user["account_name"])
    http = _httpdir(user["account_name"])

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
        forward = os.path.join(_homedir(user["account_name"]), ".forward")

        with open(forward, "w") as f:
            f.write(user["email"] + "\n")

        os.chown(forward, getpwnam(user["account_name"]).pwd_uid, getgrnam("ocf").gr_gid)

def _kerberos_add(user, principal = "root/admin", principal_password = ""):
    # Calling subprocess.Popen here because we don't have a decent
    # kerberos python module for administration commands
    user_passord = \
      _decrypt_password(base64.b64decode(user["password"]), options.rsa_priv_key)

    kadmin = Popen(["kadmin", "-p", principal], stdin = PIPE)

    # Call the add command
    kadmin.stdin.write("add --password={} --use-defaults {}\n".format(user_password, user["account_name"]))
    # XXX: Auth here with the password?
    # kadmin.stdin.write("{}\n".format(principal_password))
    kadmin.communicate()

    if kadmin.returncode != 0:
        raise RuntimeError("kdamin returned non-zero exit code: " + kadmin.returncode)

def _send_finalize_emails(users, options,
                          me = "OCF staff <help@ocf.berkeley.edu>",
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
            msg["To"] = user["email"]

            s = Popen(["sendmail", "-t"], stdin = PIPE)
            s.communicate(msg.as_string())

        # Notify staff of all the created accounts
        body = "Accounts created on {}:\n".format(datetime.now())

        for user in users:
            owner = user["group_owner" if user["is_group"] else "personal_owner"]
            body += "{}: {}\n".format(user["account_name"], owner)

        msg = MIMEText(body)
        msg["Subject"] = "Created OCF accounts"
        msg["From"] = me
        msg["To"] = staff

        s = Popen(["sendmail", "-t"], stdin = PIPE)
        s.communicate(msg.as_string())

def _get_max_uid_number(connection):
    entries = connection.search_st("ou=People,dc=OCF,dc=Berkeley,dc=EDU",
                                   ldap.SCOPE_SUBTREE, "(uid=*)", ["uidNumber"])
    uid_numbers = (int(num)
                   for entry in entries
                   for num in entry[1]["uidNumber"])

    return max(uid_numbers)

def finalize_accounts(users, options):
    users = list(users)

    # Need to assign uid to new users
    print "Getting current max uid ..."
    uid_start = _get_max_uid_number(options.ocf_ldap) + 1
    print "UIDs for new users will start at {}".format(uid_start)

    for uid, user in enumerate(users, start = uid_start):
        user["uid_number"] = uid

    for user in users:
        _finalize_account(user, options)

    _send_finalize_emails(users, options)

def _finalize_account(user, options):
    """
    Create a new account on the system.
    """

    owner = user["group_owner" if user["is_group"] else "personal_owner"]
    print "Creating new account, {}, for {}".format(user["account_name"], owner)
    return

    _ldap_add(user, options.ocf_ldap)
    _homedir_add(user)
    _forward_add(user)
    _kerberos_add(user, options.kerberos)
