"""
For the users who couldn't pick their account name right the first time.
"""

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

def _dump_crontab(user):
    pass

def _dump_ldap(user):
    pass

def _dump_pykota(user):
    pass

def _dump_mail(user):
    # Is this not all in the homedir?
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

def _add_crontab(user, new_username, dump):
    pass

def _remove_postgresql(user):
    """
    Remove a user's old postgresql database.
    """
    pass

def _remove_crontab(user):
    pass
