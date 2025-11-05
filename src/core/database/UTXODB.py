import logging
import os

logger = logging.getLogger(__name__)

from sqlitedict import SqliteDict

from src.core.database.BaseDB import BaseDB
from src.core.txs.transaction import TxOut
from src.scripts.script import Script


class UTXODB(BaseDB):
    def __init__(self):
        self.basepath = "data"
        self.db_file = os.path.join(self.basepath, "utxos.sqlite")
        self.db = SqliteDict(self.db_file, autocommit=False)
        self.meta_key_prefix = "_meta_"
        self.TxOut = TxOut
        self.Script = Script

    def get_meta(self, key):
        return self.db.get(f"{self.meta_key_prefix}{key}")

    def set_meta(self, key, value):
        self.db[f"{self.meta_key_prefix}{key}"] = value

    def commit(self):
        self.db.commit()

    def clear(self):
        keys_to_delete = [
            k for k in self.db.keys() if not k.startswith(self.meta_key_prefix)
        ]
        for k in keys_to_delete:
            del self.db[k]

    def __setitem__(self, key, tx_out_obj):
        self.db[key] = tx_out_obj.to_dict()

    def __getitem__(self, key):
        tx_out_dict = self.db.get(key)
        if tx_out_dict:
            return self.TxOut.from_dict(tx_out_dict)
        raise KeyError(f"UTXO key {key} not in set")

    def __delitem__(self, key):
        if key in self.db:
            del self.db[key]
        else:
            pass

    def __contains__(self, key):
        return key in self.db

    def __len__(self):
        return len(
            [k for k in self.db.keys() if not k.startswith(self.meta_key_prefix)]
        )

    def keys(self):
        return (k for k in self.db.keys() if not k.startswith(self.meta_key_prefix))

    def values(self):
        for k in self.keys():
            yield self[k]  # Use __getitem__ to deserialize

    def items(self):
        for k in self.keys():
            yield (k, self[k])

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def get_balances(self, wallet_h160_list):
        balances = {h160.hex(): 0 for h160 in wallet_h160_list}
        wallet_h160_set = set(wallet_h160_list)
        for tx_out_dict in self.db.values():
            if not isinstance(tx_out_dict, dict) or "script_pubkey" not in tx_out_dict:
                continue

            try:
                pubKeyHash_hex = tx_out_dict["script_pubkey"]["cmds"][2]
                pubKeyHash_bytes = bytes.fromhex(pubKeyHash_hex)
                if pubKeyHash_bytes in wallet_h160_set:
                    balances[pubKeyHash_hex] += tx_out_dict["amount"]
            except (
                AttributeError,
                IndexError,
                KeyError,
                TypeError,
                ValueError,
            ):
                continue
        return balances
