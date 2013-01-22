"""
Utility functions for account creation.
"""

import argparse
from contextlib import contextmanager
import errno
import fcntl
import os
import sys

# LDAP
import ldap

# Password decryption
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

RSA_CIPHER = None

def decrypt_password(password, priv_key):
    """
    Decrypt passwords using PKCS1_OAEP.

    Use an asymmetric encryption algorithm to allow the keys to be stored on disk
    Generate the public / private keys with the following code:

    >>> from Crypto.PublicKey import RSA
    >>> key = RSA.generate(2048)
    >>> open("private.pem", "w").write(key.exportKey())
    >>> open("public.pem", "w").write(key.publickey().exportKey())
    """

    global RSA_CIPHER

    if RSA_CIPHER is None:
        key = RSA.importKey(open(priv_key).read())
        RSA_CIPHER = PKCS1_OAEP.new(key)

    return RSA_CIPHER.decrypt(password)

def get_users(stream, options):
    fields = ("account_name", "personal_owner", "group_owner", "email",
              "forward", "is_group", "password", "calnet_uid")

    for line in stream:
        line = line.strip()

        if not line:
            continue

        split = line.split(":")

        if len(split) != len(fields):
            raise Exception("Incorrect number of fields: {0}".format(line))

        # Construct the user object, a dictionary of the different attributes
        # for the account to be created.
        user = dict((key, value) for key, value in zip(fields, split))

        user["forward"] = bool(int(user["forward"]))
        user["is_group"] = bool(int(user["is_group"]))

        if user["personal_owner"] == "(null)" and user["group_owner"] == "(null)":
            raise Exception("Entry is missing personal_owner and group_owner")
        if user["personal_owner"] != "(null)" and user["group_owner"] != "(null)":
            raise Exception("Entry has both personal_owner and group_owner")

        user["owner"] = user["group_owner" if user["is_group"] else "personal_owner"]

        yield user

def write_users(stream, users):
    for user in users:
        items = \
          [user["account_name"],
           user["owner"] if not user["is_group"] else "(null)",
           user["owner"] if user["is_group"] else "(null)",
           user["email"],
           str(int(user["forward"])),
           str(int(user["is_group"])),
           user["password"],
           user["calnet_uid"]]

        stream.write(":".join(items) + "\n")

def get_log_entries(stream):
    for line in stream:
        line = line.strip()

        if not line:
            continue

        l = line.split(":")

        if len(l) != 10:
            raise Exception("Line has unexpected format")

        user = {}
        user["account_name"] = l[0]
        user["owner"] = None
        user["id_number"] = None # can be calnet uid or student id (old)

        if l[1] != "(null)":
            user["owner"] = l[1]
            user["is_group"] = True
        if l[2] != "(null)":
            user["id_number"] = l[2]

        # the extra info at the end of the line isn't used
        user["staff_approver"] = l[3]
        user["staff_machine"] = l[4]

        user["created"] = bool(int(l[5]))
        user["is_group"] = bool(int(l[6]))

        yield user

@contextmanager
def fancy_open(path, mode = "r", lock = False, delete = False, pass_missing = False):
    """
    Open path as a file with mode. Combatible with python's with statement.

    Gives options to lock the file, delete after closing, and ignore a missing file.
    """
    try:
        f = open(path, mode)
    except IOError as e:
        # If we're just reading and pass_missing is set, ignore file missing
        if not (e.errno == errno.ENOENT and mode == "r" and pass_missing):
            raise e
        else:
            yield []
    else:
        if lock:
            fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield f
        finally:
            if lock:
                fcntl.flock(f, fcntl.LOCK_UN)

            f.close()

            # Race condition here? Can we remove a file before we unlock it?
            if delete:
                os.remove(path)
