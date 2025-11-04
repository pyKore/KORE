from math import log

from src.utils.crypto.crypto_hash import hash256

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def int_to_little_endian(n, length):
    """Int_to_little_endian takes an interger and return the little-endian byte sequence of length"""
    return n.to_bytes(length, "little")


def little_endian_to_int(b):
    """takes a byte sequence and returns an integer"""
    return int.from_bytes(b, "little")


def encode_base58(s):
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert to big endian integer
    num = int.from_bytes(s, "big")
    prefix = "k" * count  # test
    result = ""
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def decode_base58(s):
    num = 0

    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)

    combined = num.to_bytes(25, byteorder="big")
    checksum = combined[-4:]

    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(f"bad Address {checksum} {hash256(combined[:-4][:4])}")

    return combined[1:-4]


def read_varint(s):
    """read_varint reads a variable integer from a stream"""
    i = s.read(1)[0]
    if i == 0xFD:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xFE:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xFF:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    """encodes an integer as a varint"""
    if i < 0xFD:
        return bytes([i])
    elif i < 0x10000:
        return b"\xfd" + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    else:
        raise ValueError("integer too large: {}".format(i))


def merkle_parent_level(hashes):
    """takes a list of binary hashes and returns a list that's half of the length"""

    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])

    parent_level = []

    for i in range(0, len(hashes), 2):
        parent = hash256(hashes[i] + hashes[i + 1])
        parent_level.append(parent)
    return parent_level


def merkle_root(hashes):
    """Takes a list of binary hashes and return the merkle root"""
    current_level = hashes

    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)

    return current_level[0]


def target_to_bits(target):
    """Turns a target integer back into bits"""
    raw_bytes = target.to_bytes(32, "big")
    raw_bytes = raw_bytes.lstrip(b"\x00")  # <1>
    if not raw_bytes:
        return b"\x00\x00\x00\x00"

    if raw_bytes[0] > 0x7F:  # <2>
        exponent = len(raw_bytes) + 1
        coefficient = b"\x00" + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)  # <3>
        coefficient = raw_bytes[:3]  # <4>

    coefficient_padded = coefficient.ljust(3, b"\x00")
    new_bits = coefficient_padded[::-1] + bytes([exponent])
    return new_bits


def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256 ** (exponent - 3)
