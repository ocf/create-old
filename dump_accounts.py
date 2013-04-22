"""
Dump all of a user's data out to one object.
"""

from __future__ import with_statement, print_function

def _dump_kerberos(user, options):
    pass

def _dump_ldap(user, options):
    pass

def _dump_ldap_groups(user, options):
    pass

# Can forgo this now that OCF's postgres db is offline (Forgot this fact
# while stubbing)
def _dump_postgresl(user, options):
    """
    Dump a user's postgresql database into one object.
    """
    # Access the username with user["username"]
    pass

def _dump_mysql(user, options):
    """
    Dump a user's mysql database into one object.
    """
    # Access the username with user["username"]
    pass

def _dump_tsunami_crontab(user, options):
    pass

def _dump_crontabs(user, options):
    # What about the other crontabs for staff users?
    # death crontab, too?
    return {"tsunami": _dump_tsunami_crontab(user, options),}

def _dump_pykota(user, options):
    pass

def _dump_rt(user, options):
    # We care enough to support staff?
    pass

def _dump_wiki(user, options):
    # We care enough to support staff?
    pass

def _dump_mail(user, options):
    # Is this not all in the homedir?
    pass

def _dump_user_info(user, options):
    pass

def _dump_home_dir(user, options):
    # Probably want to copy their home dir to a tmp directory...or maybe
    # we can just forgo the dump/add paradigm for files
    pass

def _dump_web_dir(user, options):
    # See comments in _dump_home_dir
    pass

def dump_all(users, options, verbose = False):
    for user in users:
        if verbose:
            print("Dumping out user data for {0}".format(user["username"]))
