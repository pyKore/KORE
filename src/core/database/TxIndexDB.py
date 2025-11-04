import logging
import os

logger = logging.getLogger(__name__)

from sqlitedict import SqliteDict

from src.core.database.BaseDB import BaseDB


class TxIndexDB(BaseDB):
    def __init__(self):
        self.basepath = "data"
        self.db_file = os.path.join(self.basepath, "tx_index.sqlite")
        self.db = SqliteDict(self.db_file, autocommit=True)

    def __setitem__(self, tx_id_hex, block_hash_hex):
        """Stores tx_id -> block_hash mapping"""
        self.db[tx_id_hex] = block_hash_hex

    def __getitem__(self, tx_id_hex):
        """Retrieves block_hash for a given tx_id"""
        return self.db[tx_id_hex]

    def __delitem__(self, tx_id_hex):
        if tx_id_hex in self.db:
            del self.db[tx_id_hex]

    def __contains__(self, tx_id_hex):
        return tx_id_hex in self.db

    def get(self, tx_id_hex, default=None):
        return self.db.get(tx_id_hex, default)

    def clear(self):
        self.db.clear()
        self.db.commit()
