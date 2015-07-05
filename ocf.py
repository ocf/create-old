"""

"""

from __future__ import with_statement, print_function

from getpass import getuser
import os
from socket import gethostname
from time import asctime

from utils import fancy_open

MAIL_FROM_HELP = "Open Computing Facility <help@ocf.berkeley.edu>"
MAIL_FROM_BOT = "OCF Account Creation Bot <root@ocf.berkeley.edu>"

def log_creation(user, options):
    with fancy_open(options.log_file, "a", lock = True) as f:
        sections = [user["account_name"], user["owner"], user["university_uid"],
                    getuser(), gethostname(), 1, int(user["is_group"]),
                    asctime(), user["responsible"]]

        f.write(":".join([str(i) for i in sections]) + "\n")
