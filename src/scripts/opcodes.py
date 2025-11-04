from secp256k1 import PublicKey

from src.utils.crypto.crypto_hash import hash160


def op_dup(stack):

    if len(stack) < 1:
        return False
    stack.append(stack[-1])

    return True


def op_hash160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    h160 = hash160(element)
    stack.append(h160)
    return True


def op_equal(stack):
    if len(stack) < 2:
        return False

    element1 = stack.pop()
    element2 = stack.pop()

    if element1 == element2:
        stack.append(1)
    else:
        stack.append(0)

    return True


def op_verify(stack):
    if len(stack) < 1:
        False
    element = stack.pop()

    if element == 0:
        return False

    return True


def op_equalverify(stack):
    return op_equal(stack) and op_verify(stack)


def op_checksig(stack, z):
    if len(stack) < 2:
        return False

    try:
        sec_pubkey = stack.pop()
        der_signature_with_flag = stack.pop()
        der_signature = der_signature_with_flag[:-1]
        z_bytes = z.to_bytes(32, "big")
        pub_key_obj = PublicKey(sec_pubkey, raw=True)
        raw_sig_obj = pub_key_obj.ecdsa_deserialize(der_signature)
        verified = pub_key_obj.ecdsa_verify(z_bytes, raw_sig_obj)
    except Exception as e:
        verified = False

    if verified:
        stack.append(1)
    else:
        stack.append(0)

    return verified


OP_CODE_FUNCTION = {118: op_dup, 136: op_equalverify, 169: op_hash160, 172: op_checksig}
