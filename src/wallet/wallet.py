import os
import secrets
import sys

sys.path.append(os.getcwd())

from secp256k1 import PrivateKey

from src.core.database.AccountDB import AccountDB
from src.utils.crypto.crypto_hash import hash160, hash256


class wallet:
    def createKeys(self, WalletName):
        priv_key_obj = PrivateKey()
        self.privateKey = int.from_bytes(priv_key_obj.private_key, "big")
        pub_key_obj = priv_key_obj.pubkey
        compressesKey = pub_key_obj.serialize(compressed=True)

        """ RIPEMD160 Hashing Algorithm returns the hash of Compressed Public Key"""
        hsh160 = hash160(compressesKey)

        """Prefix for Mainnet"""
        main_prefix = b"\x6c"

        newAddr = main_prefix + hsh160

        """Checksum"""
        checksum = hash256(newAddr)[:4]

        newAddr = newAddr + checksum

        BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

        """Counter to find Leading zeros """
        count = 0
        for c in newAddr:
            if c == 0:
                count += 1
            else:
                break

        """ Convert to Numeric from Bytes """
        num = int.from_bytes(newAddr, "big")
        prefix = "1" * count

        result = ""

        """ BASE58 Encoding """
        while num > 0:
            num, mod = divmod(num, 58)
            result = BASE58_ALPHABET[mod] + result

        self.PublicAddress = prefix + result
        self.WalletName = WalletName

        return self.__dict__


if __name__ == "__main__":
    WalletName = input("Enter a name for your new wallet: ")
    if WalletName:
        acct = wallet()
        wallet_data = acct.createKeys(WalletName)
        AccountDB().save_wallet(WalletName, wallet_data)
    else:
        print("Wallet name is required")
