import logging

from src.core.chain.primitives.block import Block as BlockCore
from src.core.chain.validator import check_pow
from src.net.messages.p2p.block import Block as BlockMsg
from src.net.messages.p2p.getdata import GetData
from src.net.messages.p2p.getheaders import GetHeaders
from src.net.messages.p2p.headers import Headers
from src.net.messages.p2p.inv import INV_TYPE_BLOCK
from src.net.netparams import MAX_HEADERS_TO_SEND

logger = logging.getLogger(__name__)


class ChainService:
    def __init__(self, manager, db, incoming_blocks_queue):
        self.manager = manager
        self.db = db
        self.incoming_blocks_queue = incoming_blocks_queue

    def start_sync(self, peer_socket):
        with self.manager.sync_lock:
            if self.manager.is_syncing:
                logger.debug("Sync already in progress, ignoring start_sync request.")
                return
            self.manager.is_syncing = True

        logger.debug("Starting blockchain synchronization...")
        last_block = self.db.lastBlock()

        if not last_block:
            from src.core.genesis import GENESIS_BLOCK_HASH

            start_block_hash = bytes.fromhex(GENESIS_BLOCK_HASH)
        else:
            start_block_hash = bytes.fromhex(last_block["BlockHeader"]["blockHash"])

        getheaders_msg = GetHeaders(start_block=start_block_hash)
        self.manager.send_message(peer_socket, getheaders_msg)

    def handle_getheaders(self, peer_socket, peer_id_str, payload_stream):
        getheaders_msg = GetHeaders.parse(payload_stream)
        logger.debug(
            f"Received getheaders request from {peer_id_str} starting from {getheaders_msg.start_block.hex()}"
        )
        all_blocks = self.db.read()
        headers_to_send = []
        found_start = False

        if not all_blocks and getheaders_msg.start_block.hex() == "00" * 32:
            found_start = True

        if getheaders_msg.start_block.hex() == "00" * 32:
            found_start = True

        for block_data in all_blocks:
            if (
                not found_start
                and block_data["BlockHeader"]["blockHash"]
                == getheaders_msg.start_block.hex()
            ):
                found_start = True
                continue

            if found_start:
                header = BlockCore.to_obj(block_data).BlockHeader
                headers_to_send.append(header)
                if len(headers_to_send) >= MAX_HEADERS_TO_SEND:
                    break

        if found_start:
            if headers_to_send:
                logger.info(
                    f"Sending {len(headers_to_send)} headers to peer {peer_id_str}"
                )
            else:
                logger.info(f"Peer {peer_id_str} is up-to-date")

            headers_msg = Headers(headers_to_send)
            self.manager.send_message(peer_socket, headers_msg)

        elif getheaders_msg.start_block.hex() == "00" * 32 and not all_blocks:
            logger.info(f"Peer {peer_id_str} asked from genesis, we have no blocks")
            headers_msg = Headers([])
            self.manager.send_message(peer_socket, headers_msg)

        else:
            logger.warning(
                f"GetHeaders start_block {getheaders_msg.start_block.hex()} not found in main chain by peer {peer_id_str}"
            )

    def handle_headers(self, peer_socket, peer_id_str, payload_stream):
        headers_msg = Headers.parse(payload_stream)
        if not headers_msg.headers:
            logger.info(
                f"Finished headers synchronization with {peer_id_str} (received empty list)"
            )
            with self.manager.sync_lock:
                self.manager.is_syncing = False
            return

        logger.debug(
            f"Received {len(headers_msg.headers)} headers from peer {peer_id_str}"
        )

        last_known_block = self.db.lastBlock()
        if not last_known_block:
            prev_block_hash = "00" * 32
            from src.core.genesis import GENESIS_BLOCK_HASH

            last_known_block_hash_from_db = self.db.get_main_chain_tip_hash()
            if not last_known_block_hash_from_db:
                prev_block_hash = GENESIS_BLOCK_HASH
            else:
                prev_block_hash = last_known_block_hash_from_db
        else:
            prev_block_hash = last_known_block["BlockHeader"]["blockHash"]

        headers_to_request = []
        last_valid_header = None
        for header in headers_msg.headers:
            if header.prevBlockHash.hex() != prev_block_hash:
                if not headers_to_request:
                    if header.prevBlockHash.hex() == self.db.get_main_chain_tip_hash():
                        logger.debug(
                            f"Header {header.generateBlockHash()} connects to our last block"
                        )
                        prev_block_hash = self.db.get_main_chain_tip_hash()
                    else:
                        logger.error(
                            f"Header validation failed: Discontinuity in chain from {peer_id_str}"
                        )
                        return
                else:
                    logger.error(
                        f"Header validation failed: Discontinuity in peer's batch from {peer_id_str}"
                    )
                    return

            if not check_pow(header):
                logger.error(
                    f"Header validation failed: Invalid Proof of Work from {peer_id_str}"
                )
                return

            headers_to_request.append(header)
            prev_block_hash = header.generateBlockHash()
            last_valid_header = header

        if headers_to_request:
            items_to_get = [
                (INV_TYPE_BLOCK, bytes.fromhex(h.generateBlockHash()))
                for h in headers_to_request
            ]
            getdata_msg = GetData(items_to_get)
            self.manager.send_message(peer_socket, getdata_msg)

        if len(headers_msg.headers) == MAX_HEADERS_TO_SEND:
            if not last_valid_header:
                logger.debug(
                    "Reached max headers but have no last valid header, stopping sync."
                )
                return

            new_start_block_hash_hex = last_valid_header.generateBlockHash()
            new_start_block_hash_bytes = bytes.fromhex(new_start_block_hash_hex)

            logger.debug(
                f"Received max headers ({MAX_HEADERS_TO_SEND}). Requesting next batch starting from {new_start_block_hash_hex}"
            )

            getheaders_msg = GetHeaders(start_block=new_start_block_hash_bytes)
            self.manager.send_message(peer_socket, getheaders_msg)

        else:
            logger.info(
                f"Received {len(headers_msg.headers)} headers, sync is complete."
            )
            with self.manager.sync_lock:
                self.manager.is_syncing = False

    def handle_block(self, peer_socket, peer_id_str, payload_stream):
        block_obj = BlockCore.parse(payload_stream)
        block_hash = block_obj.BlockHeader.generateBlockHash()
        logger.info(
            f"Received block {block_obj.Height} ({block_hash}) from {peer_id_str}"
        )

        if self.incoming_blocks_queue is not None:
            self.incoming_blocks_queue.put(block_obj)
        else:
            logger.warning(
                "Incoming_blocks_queue not initialized in SyncManager. Block discarded"
            )

    def handle_getdata_block(self, peer_socket, item_hash):
        block_hash_hex = item_hash.hex()
        block_data = self.db.get_block(block_hash_hex)
        if block_data:
            block_obj = BlockCore.to_obj(block_data)
            block_msg = BlockMsg(
                block_obj.Height,
                block_obj.Blocksize,
                block_obj.BlockHeader,
                block_obj.Txcount,
                block_obj.Txs,
            )
            self.manager.send_message(peer_socket, block_msg)
        else:
            logger.warning(f"Peer requested Block {block_hash_hex} which we don't have")
