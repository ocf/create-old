"""
For the _users_ who couldn't pick their account name right the first time.

NO GROUPS ALLOWED.
"""

import argparse

from dump_accounts import dump_all
from add_accounts import add_all
from rm_accounts import rm_all

def _rename_user(old_user, new_user, options):
    dumps = dump_all([old_user], options)
    add_all([new_user], options, dumps = dumps)
    rm_all([old_user], options)

if __name__ == "__main__":
    print _rename_user(None, None, None)
