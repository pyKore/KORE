import logging
from threading import RLock

from src.chain.mempool import Mempool
from src.chain.validator import Validator
from src.core.block import Block
from src.core.transaction import TxOut
from src.database.utxo_manager import UTXOManager

logger = logging.getLogger(__name__)


class ChainManager:
    def __init__(self, blockchain_db, utxo_db, mempool_db, txindex_db, new_block_event):
        self.db = blockchain_db
        self.utxos = utxo_db
        self.mempool = mempool_db
        self.txindex = txindex_db
        self.new_block_event = new_block_event

        self.validator = Validator(self.utxos, self.mempool)
        self.utxo_manager = UTXOManager(self.utxos)
        self.mempool_manager = Mempool(self.mempool, self.utxos)
        self.mempool_lock = RLock()

    def add_transaction_to_mempool(self, tx):
        tx_id = tx.id()
        with self.mempool_lock:
            if tx_id in self.mempool:
                logger.warning(f"Tx {tx_id} already in mempool, rejected...")
                return False

            if not self.validator.validate_transaction(tx, is_in_block=False):
                logger.warning(f"Tx {tx_id} validation failed, rejected...")
                return False

            logger.info(f"Tx {tx_id} added in mempool")
            self.mempool[tx_id] = tx
            return True

    def process_new_block(self, block_obj):
        block_hash = block_obj.BlockHeader.generateBlockHash()
        if self.db.get_block(block_hash):
            logger.debug(f"Block {block_hash} already known. Discarding...")
            return False

        if not self.validator.validate_block_header(block_obj.BlockHeader, self.db):
            logger.warning(
                f"Block {block_hash} failed header validation. Discarding..."
            )
            return False

        if not self.validator.validate_block_body(block_obj, self.db):
            logger.warning(f"Block {block_hash} failed body validation. Discarding...")
            return False

        block_dict = self.block_to_dict(block_obj)
        self.db.write_block(block_dict)

        logger.info(
            f"Accepted new block: {block_obj.Height} (hash: {block_hash[:10]}...)"
        )
        main_tip_hash = self.db.get_main_chain_tip_hash()
        if not main_tip_hash:
            logger.debug("Processing Genesis block")
            self.connect_block(block_obj)
            self.db.set_main_chain_tip(block_hash)
            return True

        main_tip_index = self.db.get_index(main_tip_hash)
        new_block_index = self.db.get_index(block_hash)

        if new_block_index["total_work"] > main_tip_index["total_work"]:
            logger.info(f"New block {block_hash} has more work. Reorganizing chain...")
            self.reorganize_chain(block_hash)
        else:
            logger.info(
                f"New block {block_hash} is on a fork with less work. Storing..."
            )

        return True

    def reorganize_chain(self, new_tip_hash):
        new_chain = []
        old_chain = []

        curr_new_hash = new_tip_hash
        curr_old_hash = self.db.get_main_chain_tip_hash()

        while curr_new_hash != curr_old_hash:
            new_idx = self.db.get_index(curr_new_hash)
            old_idx = self.db.get_index(curr_old_hash)

            if not new_idx:
                break

            if not old_idx or new_idx["height"] > old_idx["height"]:
                new_chain.append(curr_new_hash)
                curr_new_hash = new_idx["prev_hash"]
            elif new_idx["height"] < old_idx["height"]:
                old_chain.append(curr_old_hash)
                curr_old_hash = old_idx["prev_hash"]
            else:
                new_chain.append(curr_new_hash)
                old_chain.append(curr_old_hash)
                curr_new_hash = new_idx["prev_hash"]
                curr_old_hash = old_idx["prev_hash"]

        common_ancestor_hash = curr_new_hash
        logger.debug(f"Common ancestor is {common_ancestor_hash}")

        blocks_to_disconnect = []
        for block_hash in old_chain:
            block = self.db.get_block(block_hash)
            if not block:
                logger.error(f"Block {block_hash} not in DB during reorg. Stopping...")
                return False
            blocks_to_disconnect.append(Block.to_obj(block))

        blocks_to_connect = []
        for block_hash in reversed(new_chain):
            block = self.db.get_block(block_hash)
            if not block:
                logger.error(f"Block {block_hash} not in DB during reorg. Stopping...")
                return False
            blocks_to_connect.append(Block.to_obj(block))

        connected_blocks = []
        try:
            for block_obj in blocks_to_disconnect:
                logger.debug(
                    f"Disconnecting block {block_obj.Height} (hash: {block_obj.BlockHeader.generateBlockHash()[:10]}...)"
                )
                self.disconnect_block(block_obj)

            for block_obj in blocks_to_connect:
                logger.debug(
                    f"Connecting block {block_obj.Height} (hash: {block_obj.BlockHeader.generateBlockHash()[:10]}...)"
                )
                if not self.connect_block(block_obj):
                    raise Exception(
                        f"Failed to connect block {block_obj.Height} ({block_obj.BlockHeader.generateBlockHash()})"
                    )
                connected_blocks.append(block_obj)

            logger.debug(f"Reorganization successful. New tip: {new_tip_hash}")
            self.db.set_main_chain_tip(new_tip_hash)
            self.utxos.set_meta("last_block_hash", new_tip_hash)
            self.utxos.commit()

            self.new_block_event.set()

        except Exception as e:
            logger.critical(f"Reorganization failed: {e}. Attempting state rollback...")
            for block_obj in reversed(connected_blocks):
                logger.warning(
                    f"Rollback: Disconnecting new block {block_obj.Height} ({block_obj.BlockHeader.generateBlockHash()[:10]}...)"
                )
                self.disconnect_block(block_obj)

            original_tip_hash = common_ancestor_hash
            for block_obj in reversed(blocks_to_disconnect):
                logger.warning(
                    f"Rollback: Re-connecting old block {block_obj.Height} ({block_obj.BlockHeader.generateBlockHash()[:10]}...)"
                )
                if not self.connect_block(block_obj):
                    logger.critical(
                        f"Rollback FAILED. Could not re-connect block {block_obj.Height}"
                    )
                    logger.critical(
                        "CHAIN STATE IS CORRUPTED. MANUAL INTERVENTION REQUIRED"
                    )
                    return False

                original_tip_hash = block_obj.BlockHeader.generateBlockHash()

            logger.info(
                f"Rollback complete. Chain restored to original tip: {original_tip_hash}"
            )
            self.db.set_main_chain_tip(original_tip_hash)
            self.utxos.set_meta("last_block_hash", original_tip_hash)
            self.utxos.commit()

            return False

        return True

    def connect_block(self, block_obj):
        if not self.validator.validate_block_transactions(block_obj, is_in_block=True):
            logger.warning(
                f"Block {block_obj.Height} failed context-full tx validation. Aborting connect"
            )
            return False

        block_hash = block_obj.BlockHeader.generateBlockHash()
        tx_ids_in_block = []

        for tx in block_obj.Txs:
            tx_id = tx.id()
            tx_ids_in_block.append(bytes.fromhex(tx_id))
            self.txindex[tx_id] = block_hash

        spent_outputs = [
            [tx_in.prev_tx, tx_in.prev_index]
            for tx in block_obj.Txs[1:]
            for tx_in in tx.tx_ins
        ]

        self.utxo_manager.remove_spent_utxos(spent_outputs)
        self.utxo_manager.add_new_outputs_from_block(block_obj)

        self.mempool_manager.remove_transactions(tx_ids_in_block)

        logger.debug(f"Connected block {block_obj.Height}. UTXOs and mempool updated")
        return True

    def disconnect_block(self, block_obj):
        for tx in block_obj.Txs:
            tx_id_hex = tx.id()
            if tx_id_hex in self.txindex:
                del self.txindex[tx_id_hex]

            for i in range(len(tx.tx_outs)):
                key = f"{tx_id_hex}_{i}"
                if key in self.utxos:
                    del self.utxos[key]

        for tx in block_obj.Txs[1:]:
            for tx_in in tx.tx_ins:
                prev_tx_hash = tx_in.prev_tx.hex()
                prev_tx_index = tx_in.prev_index
                prev_tx_block_dict = self.find_tx_block_in_chain(prev_tx_hash)
                if not prev_tx_block_dict:
                    logger.warning(
                        f"Corruption detected: txindex doesn't find {prev_tx_hash} during disconnect"
                    )
                    continue

                found_parent_tx = False
                for tx_dict in prev_tx_block_dict["Txs"]:
                    if tx_dict["TxId"] == prev_tx_hash:
                        try:
                            tx_out_dict = tx_dict["tx_outs"][prev_tx_index]
                            if tx_out_dict is None:
                                logger.warning(
                                    f"Tried to disconnect and restore a 'None' output for {prev_tx_hash}_{prev_tx_index}"
                                )
                                continue
                            tx_out_obj = TxOut.from_dict(tx_out_dict)
                            key = f"{prev_tx_hash}_{prev_tx_index}"
                            self.utxos[key] = tx_out_obj
                            found_parent_tx = True
                            break
                        except (IndexError, KeyError) as e:
                            logger.error(
                                f"Failed to parse tx_out from stored block: {e}"
                            )

                if not found_parent_tx:
                    logger.warning(
                        f"Corruption detected: block {prev_tx_block_dict['Height']} found but doesn't have tx {prev_tx_hash}"
                    )

        for tx in block_obj.Txs[1:]:
            tx_id = tx.id()
            if tx_id not in self.mempool:
                if self.validator.validate_transaction(tx, is_in_block=False):
                    self.mempool[tx_id] = tx
                else:
                    logger.debug(
                        f"Orphaned tx {tx_id} is no longer valid. Discarding..."
                    )

        logger.debug(
            f"Disconnected block {block_obj.Height}. UTXOs restored, txs returned to mempool"
        )
        return True

    def find_tx_block_in_chain(self, tx_id):
        block_hash = self.txindex.get(tx_id)
        if not block_hash:
            logger.warning(f"Transaction {tx_id} not found in txindexDB")
            return None

        block = self.db.get_block(block_hash)
        if not block:
            logger.error(
                f"txindex points to block {block_hash} for tx {tx_id}, but block is not in DB"
            )
            return None

        return block

    def block_to_dict(self, block):
        block.BlockHeader.to_hex()
        tx_json_list = [tx.to_dict() for tx in block.Txs]
        return {
            "Height": block.Height,
            "Blocksize": block.Blocksize,
            "BlockHeader": block.BlockHeader.__dict__,
            "TxCount": len(tx_json_list),
            "Txs": tx_json_list,
        }
