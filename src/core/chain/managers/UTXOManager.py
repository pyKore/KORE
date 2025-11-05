import logging

logger = logging.getLogger(__name__)

from src.core.database.BlockchainDB import BlockchainDB
from src.core.txs.transaction import Tx, TxOut


class UTXOManager:
    def __init__(self, utxos):
        self.utxos = utxos

    def build_utxos_from_db(self):
        all_txs = {}
        blocks = BlockchainDB().read()

        spent_outputs = set()
        for block in blocks:
            for tx in block["Txs"]:
                if tx["tx_ins"][0]["prev_tx"] == "00" * 32:
                    continue
                for txin in tx["tx_ins"]:
                    spent_key = f"{txin['prev_tx']}_{txin['prev_index']}"
                    spent_outputs.add(spent_key)

        self.utxos.clear()

        for block in blocks:
            for tx_dict in block["Txs"]:
                tx_id = tx_dict["TxId"]
                for index, tx_out_dict in enumerate(tx_dict["tx_outs"]):
                    spend_key = f"{tx_id}_{index}"
                    if spend_key not in spent_outputs:
                        tx_out_obj = TxOut.from_dict(tx_out_dict)
                        self.utxos[spend_key] = tx_out_obj

        logging.debug(f"UTXO set rebuilt. Found {len(self.utxos)} unspent outputs")

    def add_new_outputs_from_block(self, block_obj):
        for tx in block_obj.Txs:
            tx_id = tx.id()
            for index, tx_out in enumerate(tx.tx_outs):
                if tx_out:
                    self.utxos[f"{tx_id}_{index}"] = tx_out

    def remove_spent_utxos(self, spent_outputs):
        if not spent_outputs:
            return

        for tx_id_bytes, output_index in spent_outputs:
            key = f"{tx_id_bytes.hex()}_{output_index}"
            if key in self.utxos:
                del self.utxos[key]
            else:
                logging.warning(
                    f"Tried to spend a non-existent or already-spent UTXO: {key}"
                )
