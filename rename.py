"""
For the _users_ who couldn't pick their account name right the first time.

NO GROUPS ALLOWED.
"""

import os
import sys
import types

# See https://rt.ocf.berkeley.edu/Ticket/Display.html?id=638 for a list of
# all the things to copy over

# Can forgoe this now that OCF's postgres db is offline (Forgot this fact
# while stubbing)
def _dump_postgresl(user):
    """
    Dump a user's postgresql database into one object.
    """
    # Access the username with user["username"]
    pass

def _dump_mysql(user):
    """
    Dump a user's mysql database into one object.
    """
    # Access the username with user["username"]
    pass

def _dump_tsunami_crontab(user):
    pass

def _dump_crontabs(user):
    # What about the other crontabs for staff users?
    # death crontab, too?
    return {"tsunami": _dump_tsunami_crontab(user),}

def _dump_kerberos(user):
    pass

def _dump_ldap(user):
    pass

def _dump_ldap_groups(user):
    pass

def _dump_pykota(user):
    pass

def _dump_rt(user):
    # We care enough to support staff?
    pass

def _dump_wiki(user):
    # We care enough to support staff?
    pass

def _dump_mail(user):
    # Is this not all in the homedir?
    pass

def _dump_user_info(user):
    pass

def _dump_homedir(user):
    # Probably want to copy their homedir to a tmp directory...or maybe
    # we can just forgoe the dump/add paradigm for files
    pass

def _dump_webdir(user):
    # See comments in _dump_homedir
    pass

def _add_postgresql(user, new_username, dump):
    """
    Re-add a user's postgresql database.
    """
    pass

def _add_mysql(user, new_username, dump):
    """
    Adds a user's mysql tables back into the OCF database.
    """
    # Access the username with user["username"]
    pass

def _add_tsunami_crontab(user, new_username, dump):
    pass

def _add_crontabs(user, new_username, dump):
    _add_tsunami_crontab(user, new_username, dump["tsunami"])

def _add_kerberos(user, new_username, dump):
    pass

def _add_ldap(user, new_username, dump):
    pass

def _add_ldap_groups(user, new_username, dump):
    pass

def _add_pykota(user, new_username, dump):
    pass

def _add_rt(user, new_username, dump):
    # We care enough to support staff?
    pass

def _add_wiki(user, new_username, dump):
    # We care enough to support staff?
    pass

def _add_mail(user, new_username, dump):
    # Is this not all in the homedir?
    pass

def _add_user_info(user, new_username, dump):
    pass

def _add_homedir(user, new_username, dump):
    # Probably want to copy their homedir to a tmp directory...or maybe
    # we can just forgoe the dump/add paradigm for files
    pass

def _add_webdir(user, new_username, dump):
    # See comments in _add_homedir
    pass

def _remove_postgresql(user):
    """
    Remove a user's old postgresql database.
    """
    pass

def _remove_mysql(user):
    """
    Removes a user's mysql tables from the OCF database.
    """
    # Access the username with user["username"]
    pass

def _remove_tsunami_crontab(user):
    pass

def _remove_crontabs(user):
    _remove_tsunami_crontab(user)

def _remove_kerberos(user):
    pass

def _remove_ldap(user):
    pass

def _remove_ldap_groups(user):
    pass

def _remove_pykota(user):
    pass

def _remove_rt(user):
    # We care enough to support staff?
    pass

def _remove_wiki(user):
    # We care enough to support staff?
    pass

def _remove_mail(user):
    # Is this not all in the homedir?
    pass

def _remove_user_info(user):
    pass

def _remove_homedir(user):
    # Probably want to copy their homedir to a tmp directory...or maybe
    # we can just forgoe the dump/add paradigm for files
    pass

def _remove_webdir(user):
    # See comments in _remove_homedir
    pass

def _rename_user(user, new_username):
    # It's incredibly temping to just dir() the module and iterate over
    # all functions starting with _dump_, _add_, _remove_...
    for var, f in globals().items():
        if var.startswith("_dump_") and isinstance(f, types.FunctionType):
            print var

    for var, f in globals().items():
        if var.startswith("_add_") and isinstance(f, types.FunctionType):
            print var

    for var, f in globals().items():
        if var.startswith("_remove_") and isinstance(f, types.FunctionType):
            print var

    return

if __name__ == "__main__":
    print _rename_user(None, None)
