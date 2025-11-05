import logging

from src.net.messages.p2p import (
    Addr,
    GetAddr,
    GetData,
    Inv,
    Ping,
    Pong,
    Tx,
    VerAck,
    Version,
)
from src.net.messages.p2p.inv import INV_TYPE_BLOCK, INV_TYPE_TX

logger = logging.getLogger(__name__)


class PeerService:
    def __init__(self, manager, db, mempool, chain_manager):
        self.manager = manager
        self.db = db
        self.mempool = mempool
        self.chain_manager = chain_manager

    def handle_version(self, peer_socket, peer_id_str, payload_stream):
        peer_version = Version.parse(payload_stream)
        logger.debug(
            f"Handling Version from {peer_id_str} (Height: {peer_version.start_height})"
        )

        last_block = self.db.lastBlock()
        our_height = last_block["Height"] if last_block else 0
        if self.manager.peer_handshake_status.get(peer_id_str) is None:
            version_msg = Version(start_height=our_height)
            self.manager.send_message(peer_socket, version_msg)

        verack_msg = VerAck()
        self.manager.send_message(peer_socket, verack_msg)

        self.manager.peer_handshake_status[peer_id_str] = {
            "version_received": True,
            "verack_received": False,
        }

        if peer_version.start_height > our_height:
            logger.info(
                f"Peer {peer_id_str} has a longer chain (height {peer_version.start_height} vs our {our_height}). Starting sync..."
            )
            if hasattr(self.manager, "chain_service"):
                self.manager.chain_service.start_sync(peer_socket)
            else:
                logger.error("ChainService not initialized in SyncManager!")

    def handle_verack(self, peer_socket, peer_id_str, payload_stream):
        if (
            peer_id_str in self.manager.peer_handshake_status
            and self.manager.peer_handshake_status[peer_id_str]["version_received"]
        ):
            self.manager.peer_handshake_status[peer_id_str]["verack_received"] = True
            logger.debug(
                f"Handshake complete with {peer_id_str}. Connection established."
            )
        else:
            logger.warning(f"Received unexpected VerAck from {peer_id_str}.")

    def handle_ping(self, peer_socket, peer_id_str, payload_stream):
        ping_msg = Ping.parse(payload_stream)
        pong_msg = Pong(ping_msg.nonce)
        self.manager.send_message(peer_socket, pong_msg)

    def handle_pong(self, peer_socket, peer_id_str, payload_stream):
        pong_msg = Pong.parse(payload_stream)
        logger.debug(f"Pong received from {peer_id_str} (Nonce: {pong_msg.nonce})")

    def handle_getaddr(self, peer_socket, peer_id_str, payload_stream):
        GetAddr.parse(payload_stream)
        known_peers = []
        with self.manager.peers_lock:
            for peer_id in self.manager.peers:
                try:
                    host, port_str = peer_id.rsplit(":", 1)
                    known_peers.append((host, int(port_str)))
                except ValueError:
                    continue
        addr_msg = Addr(known_peers)
        self.manager.send_message(peer_socket, addr_msg)

    def handle_addr(self, peer_socket, peer_id_str, payload_stream):
        addr_message = Addr.parse(payload_stream)
        logger.debug(
            f"Received {len(addr_message.addresses)} new addresses from {peer_id_str}"
        )
        for new_host, new_port in addr_message.addresses:
            self.manager.connect_to_peer(new_host, new_port)

    # --- Mempool & Inventory Logic ---

    def handle_inv(self, peer_socket, peer_id_str, payload_stream):
        inv_msg = Inv.parse(payload_stream)
        items_to_get = []
        for item_type, item_hash in inv_msg.items:
            if item_type == INV_TYPE_TX:
                if item_hash.hex() not in self.mempool:
                    items_to_get.append((INV_TYPE_TX, item_hash))
            elif item_type == INV_TYPE_BLOCK:
                if not self.db.get_block(item_hash.hex()):
                    items_to_get.append((INV_TYPE_BLOCK, item_hash))
            else:
                logger.warning(
                    f"Received unknown Inv type {item_type} from {peer_id_str}"
                )

        if items_to_get:
            logger.debug(
                f"Requesting {len(items_to_get)} items from {peer_id_str} via GetData"
            )
            getdata_msg = GetData(items_to_get)
            self.manager.send_message(peer_socket, getdata_msg)

    def handle_tx(self, peer_socket, peer_id_str, payload_stream):
        tx_obj = Tx.parse(payload_stream)
        tx_id = tx_obj.id()
        if not self.chain_manager:
            logger.warning(f"ChainManager not available. Tx {tx_id} rejected.")
            return

        try:
            tx_was_added = self.chain_manager.add_transaction_to_mempool(tx_obj)

            if tx_was_added:
                if self.manager.is_syncing:
                    logger.info(
                        f"Tx {tx_id} added to mempool (IBD in progress, not broadcasting)"
                    )
                else:
                    logger.info(f"Tx {tx_id} added, broadcasting...")
                    self.manager.broadcast_tx(tx_obj, origin_peer_socket=peer_socket)
        except Exception as e:
            logger.error(f"Error processing Tx {tx_id} from {peer_id_str}: {e}")

    def handle_getdata_router(self, peer_socket, peer_id_str, payload_stream):
        getdata_msg = GetData.parse(payload_stream)
        for item_type, item_hash in getdata_msg.items:
            if item_type == INV_TYPE_TX:
                self.handle_getdata_tx(peer_socket, item_hash)
            elif item_type == INV_TYPE_BLOCK:
                if hasattr(self.manager, "chain_service"):
                    self.manager.chain_service.handle_getdata_block(
                        peer_socket, item_hash
                    )
                else:
                    logger.error("ChainService not available for GetData(Block)")

    def handle_getdata_tx(self, peer_socket, item_hash):
        tx_id = item_hash.hex()
        if tx_id in self.mempool:
            tx_obj = self.mempool[tx_id]
            tx_msg = Tx(tx_obj.version, tx_obj.tx_ins, tx_obj.tx_outs, tx_obj.locktime)
            self.manager.send_message(peer_socket, tx_msg)
        else:
            logger.warning(f"Peer requested Tx {tx_id} which we don't have in mempool.")
