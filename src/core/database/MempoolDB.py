import logging
import os
import time

logger = logging.getLogger(__name__)

from sqlitedict import SqliteDict

from src.core.database.BaseDB import BaseDB
from src.core.txs.transaction import Tx


class MempoolDB(BaseDB):
    def __init__(self):
        self.basepath = "data"
        self.db_file = os.path.join(self.basepath, "mempool.sqlite")
        self.db = SqliteDict(self.db_file, autocommit=True)

    def __setitem__(self, tx_id_hex, tx_obj):
        store_data = {
            "tx_dict": tx_obj.to_dict(),
            "fee": getattr(tx_obj, "fee", 0),
            "received_time": getattr(tx_obj, "receivedTime", time.time()),
        }
        self.db[tx_id_hex] = store_data

    def __getitem__(self, tx_id_hex):
        stored = self.db.get(tx_id_hex)
        if not stored:
            raise KeyError(f"Tx {tx_id_hex} not in mempool")
        tx_obj = Tx.to_obj(stored["tx_dict"])
        tx_obj.fee = stored["fee"]
        tx_obj.receivedTime = stored["received_time"]
        return tx_obj

    def __delitem__(self, tx_id_hex):
        if tx_id_hex in self.db:
            del self.db[tx_id_hex]

    def __contains__(self, tx_id_hex):
        return tx_id_hex in self.db

    def __len__(self):
        return len(self.db)

    def keys(self):
        return self.db.keys()

    def values(self):
        for k in self.keys():
            yield self[k]  # Use __getitem__ to deserialize

    def items(self):
        for k in self.keys():
            yield (k, self[k])

    def clear(self):
        self.db.clear()
        self.db.commit()
