"""
"""

from __future__ import with_statement, print_function

import errno
import pexpect
import shutil

import ldap

from ocf import home_dir, http_dir, OCF_DN

def _rm_all_kerberos(users, options, domain = "OCF.BERKELEY.EDU"):
    principal = "{0}/admin".format(options.admin_user)

    # We don't want to keep spawning new kadmin processes for each user, remove
    # all their kerberos principals together
    kadmin = pexpect.spawn("kadmin", ["-p", principal])
    kadmin.expect("kadmin> ")

    for user in users:
        kadmin.sendline("del {0}".format(user["account_name"]))

        i = 0

        while i == 0:
            i = kadmin.expect(
                ["{0}@{1}'s Password:".format(principal, domain),
                 "kadmin> ",
                 "kadmin: [^\n]*"])

            if i == 0:
                kadmin.sendline(options.admin_password)
            elif i == 2:
                print(kadmin.match.group(0))
                kadmin.expect("kadmin> ")

    kadmin.sendline("exit")
    kadmin.expect(pexpect.EOF)

def _rm_ldap(user, options):
    dn = "uid={0},{1}".format(user["account_name"], OCF_DN)

    try:
        options.ocf_ldap.delete_s(dn)
    except ldap.NO_SUCH_OBJECT:
        print("{0} does not exist in ldap".format(dn))

def _rm_mysql(user, options):
    """
    Removes a user's mysql tables from the OCF database.
    """
    pass

def _rm_postgresql(user, options):
    """
    Remove a user's old postgresql database.
    """
    pass

def _rm_pykota(user):
    pass

def _rm_tsunami_crontab(user):
    pass

def _rm_crontabs(user):
    _rm_tsunami_crontab(user)

def _rm_ldap_groups(user):
    pass

def _rm_rt(user):
    # We care enough to support staff?
    pass

def _rm_wiki(user):
    # We care enough to support staff?
    pass

def _rm_mail(user):
    # Is this not all in the homedir?
    pass

def _rm_user_info(user):
    pass

def _rm_home_dir(user):
    # Probably want to copy their homedir to a tmp directory...or maybe
    # we can just forgo the dump/add paradigm for files
    try:
        shutil.rmtree(home_dir(user["account_name"]))
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise e

def _rm_web_dir(user):
    # See comments in _rm_home_dir
    try:
        shutil.rmtree(http_dir(user["account_name"]))
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise e

def rm_all(users, options):
    _rm_all_kerberos(users, options)

    for user in users:
        _rm_ldap(user, options)
        _rm_home_dir(user)
        _rm_web_dir(user)
        _rm_mail(user)
        _rm_mysql(user, options)
        _rm_postgresql(user, options)
