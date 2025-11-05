class Mempool:
    def __init__(self, mempool, utxos):
        self.mempool = mempool
        self.utxos = utxos

    def _is_double_spend(self, tx, block_pending_txs):
        for txin in tx.tx_ins:
            if txin.prev_tx in block_pending_txs:
                return True
            utxo_key = f"{txin.prev_tx.hex()}_{txin.prev_index}"
            if utxo_key not in self.utxos:
                return True
        return False

    def get_transactions_for_block(self):
        block_size = 80
        tx_ids_for_block = []
        txs_for_block = []
        spent_utxos_for_block = []
        prev_txs_in_block = []
        delete_txs_from_mempool = []
        temp_mempool_list = []

        for tx_id, tx in self.mempool.items():
            tx_size = len(tx.serialize())
            fee = getattr(tx, "fee", 0)
            received_time = getattr(tx, "received_time", 0)

            if tx_size > 0:
                fee_rate = fee / tx_size
                temp_mempool_list.append(
                    {
                        "tx_id": tx_id,
                        "tx_obj": tx,
                        "fee_rate": fee_rate,
                        "received_time": received_time,
                    }
                )
        sorted_mempool = sorted(
            temp_mempool_list,
            key=lambda x: (x["fee_rate"], x["received_time"]),
            reverse=True,
        )

        for tx_data in sorted_mempool:
            tx_id = tx_data["tx_id"]
            tx = tx_data["tx_obj"]
            tx_size = len(tx.serialize())

            if block_size + tx_size > 1000000:
                continue  # here

            if not self._is_double_spend(tx, prev_txs_in_block):
                tx.TxId = tx_id
                tx_ids_for_block.append(bytes.fromhex(tx_id))
                txs_for_block.append(tx)
                block_size += tx_size

                for spent in tx.tx_ins:
                    prev_txs_in_block.append(spent.prev_tx)
                    spent_utxos_for_block.append([spent.prev_tx, spent.prev_index])
            else:
                delete_txs_from_mempool.append(tx_id)

        for tx_id in delete_txs_from_mempool:
            if tx_id in self.mempool:
                del self.mempool[tx_id]

        input_amount = 0
        output_amount = 0

        for tx_id_bytes, output_index in spent_utxos_for_block:
            tx_id_hex = tx_id_bytes.hex()
            key = f"{tx_id_hex}_{output_index}"
            if key in self.utxos:
                tx_out_obj = self.utxos[key]
                input_amount += tx_out_obj.amount

        for tx in txs_for_block:
            for tx_out in tx.tx_outs:
                output_amount += tx_out.amount

        total_fees = input_amount - output_amount

        return {
            "transactions": txs_for_block,
            "tx_ids": tx_ids_for_block,
            "block_size": block_size,
            "fees": total_fees,
        }

    def remove_transactions(self, tx_ids):
        for tx_id_bytes in tx_ids:
            tx_id_hex = tx_id_bytes.hex()
            if tx_id_hex in self.mempool:
                del self.mempool[tx_id_hex]
