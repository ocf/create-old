"""

"""

import os

OCF_DN = "ou=People,dc=OCF,dc=Berkeley,dc=EDU"

def home_dir(account_name):
    """
    Returns the user's home directory: "/home/u/us/account_name".
    """
    return os.path.sep + \
      os.path.join("home", account_name[0], account_name[:2], account_name)

def http_dir(account_name):
    """
    Returns the user's http directory: "/services/http/users/u/account_name".
    """
    return os.path.sep + \
      os.path.join("services", "http", "users", account_name[0], account_name)
