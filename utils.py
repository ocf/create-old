"""
Utility functions for account creation.
"""

import argparse
from contextlib import contextmanager
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
    fields = ("username", "real_name", "group_name", "email",
              "forward", "group", "password", "key", "university_id")

    for line in stream:
        line = line.strip()

        if not line:
            continue

        split = line.split(":")

        if len(split) != len(fields):
            print >>sys.stderr, "line has incorrect number of fields:", line # log.warn?
            sys.exit()

        # Construct the user object, a dictionary of the different attributes
        # for the account to be created.
        user = dict((key, value) for key, value in zip(fields, split))

        user["password"] = \
          base64.b64encode(_decrypt_password(user["password"], options.rsa_priv_key))
        user["forward"] = bool(int(user["forward"]))
        user["group"] = bool(int(user["group"]))

        yield user

@contextmanager
def fancy_open(path, mode = "r", lock = False, delete = False):
    """
    Open path as a file with mode. Combatible with python's with statement.

    Gives options to lock the file and delete after closing.
    """
    f = open(path, mode)

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
