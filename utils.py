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

class LDAPAction(argparse.Action):
    """
    An action to automatically open LDAP connections, given the URL passed as the
    option's value.
    """
    def __call__(self, parser, namespace, values, option_string = None):
        # Connect to LDAP
        connection = ldap.initialize(values)

        # if option_string in ["-c", "--calnetldap"]: use different credentials?
        connection.simple_bind_s('','')

        setattr(namespace, self.dest, connection)

def get_users(stream, options):
    fields = ("account_name", "personal_owner", "group_owner", "email",
              "forward", "is_group", "password", "key", "calnet_uid")

    for line in stream:
        line = line.strip()

        if not line:
            continue

        split = line.split(":")

        if len(split) != len(fields):
            raise Exception("Incorrect number of fields: {}".format(line))

        # Construct the user object, a dictionary of the different attributes
        # for the account to be created.
        user = dict((key, value) for key, value in zip(fields, split))

        user["password"] = \
          base64.b64encode(_decrypt_password(user["password"], options.rsa_priv_key))
        user["forward"] = bool(int(user["forward"]))
        user["is_group"] = bool(int(user["is_group"]))

        if user["personal_owner"] is None and user["group_owner"] is None:
            raise Exception("Entry is missing personal_owner and group_owner")
        if user["personal_owner"] is not None and user["group_owner"] is not None:
            raise Exception("Entry has both personal_owner and group_owner")

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
            fcntl.flock(f, fnctl.LOCK_EX)
        try:
            yield f
        finally:
            f.close()

            if lock:
                fcntl.flock(f, fnctl.LOCK_UN)

            # Race condition here? Can we remove a file before we unlock it?
            if delete:
                os.remove(path)