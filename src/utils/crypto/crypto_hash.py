import hashlib

from Crypto.Hash import RIPEMD160


def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def hash160(s):
    return RIPEMD160.new(hashlib.sha256(s).digest()).digest()
