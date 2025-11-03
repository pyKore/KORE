import logging
import socket
import time
from threading import Lock, RLock, Thread

from src.chain.mempool import Mempool
from src.chain.params import MAX_HEADERS_TO_SEND, MAX_PEERS, PING_INTERVAL
from src.chain.validator import Validator, check_pow
from src.database.db_manager import BlockchainDB
from src.database.utxo_manager import UTXOManager
from src.net.connection import Node
from src.net.messages import (
    INV_TYPE_BLOCK,
    INV_TYPE_TX,
    Addr,
    Block,
    GetAddr,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Ping,
    Pong,
    Tx,
    VerAck,
    Version,
)
from src.net.protocol import NetworkEnvelope

logger = logging.getLogger(__name__)


class SyncManager:
    def __init__(
        self,
        host,
        port,
        new_block_event=None,
        mempool=None,
        utxos=None,
        chain_manager=None,
        incoming_blocks_queue=None,
    ):
        self.host = host
        self.port = port
        self.new_block_event = new_block_event
        self.mempool = mempool
        self.utxos = utxos
        self.chain_manager = chain_manager

        self.validator = Validator(self.utxos, self.mempool)
        self.db = BlockchainDB()

        self.utxo_manager = UTXOManager(self.utxos)
        self.mempool_manager = Mempool(self.mempool, self.utxos)

        self.incoming_blocks_queue = incoming_blocks_queue

        self.peer_handshake_status = {}
        self.peers = {}
        self.peers_lock = RLock()

        self.last_ping_sent = {}
        self.sync_lock = Lock()
        self.is_syncing = False

    def send_message(self, sock, message):
        envelope = NetworkEnvelope(message.command, message.serialize())
        sock.sendall(envelope.serialize())
        pass

    def connect_to_peer(self, host, port):
        peer_id = f"{host}:{port}"
        with self.peers_lock:
            if peer_id in self.peers or (self.host == host and self.port == port):
                return

            if len(self.peers) >= MAX_PEERS:
                logger.debug(
                    f"Cannot connect to peer {peer_id}: max peers ({MAX_PEERS}) reached"
                )
                return
        try:
            peer_node = Node(host, port)
            client_socket = peer_node.connect(self.port)

            last_block = self.db.lastBlock()
            start_height = last_block["Height"] if last_block else 0
            version_msg = Version(start_height=start_height)
            self.send_message(client_socket, version_msg)

            handler_thread = Thread(
                target=self.handle_connection, args=(client_socket, (host, port))
            )
            handler_thread.daemon = True
            handler_thread.start()

        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}. Error: {e}")

    def start_ping_thread(self):
        def ping_peers():
            while True:
                with self.peers_lock:
                    for peer_id, conn in list(self.peers.items()):
                        if time.time() - self.last_ping_sent.get(peer_id, 0) > 60:
                            try:
                                ping_msg = Ping()
                                self.send_message(conn, ping_msg)
                                self.last_ping_sent[peer_id] = time.time()
                            except Exception as e:
                                logger.error(f"Failed to send ping to {peer_id}: {e}")
                time.sleep(PING_INTERVAL)

        ping_thread = Thread(target=ping_peers)
        ping_thread.daemon = True
        ping_thread.start()

    def spin_up_the_server(self):
        self.server = Node(self.host, self.port)
        self.server.startServer()
        logger.info(f"[LISTENING] at {self.host}:{self.port}")

        self.start_ping_thread()

        while True:
            conn, addr = self.server.acceptConnection()
            handler_thread = Thread(target=self.handle_connection, args=(conn, addr))
            handler_thread.daemon = True
            handler_thread.start()

    def handle_connection(self, conn, addr):
        peer_id_str = f"{addr[0]}:{addr[1]}"
        logger.info(f"Handling new connection from {peer_id_str}")

        with self.peers_lock:
            if len(self.peers) >= MAX_PEERS:
                logger.warning(
                    f"Refusing connection from {peer_id_str}: max peers ({MAX_PEERS}) reached"
                )
                try:
                    conn.close()
                except Exception as e:
                    logger.debug(f"Error closing refused connection: {e}")
                return

            self.peers[peer_id_str] = conn

        try:
            stream = conn.makefile("rb", None)

            while True:
                try:
                    envelope = NetworkEnvelope.parse(stream)
                    command = envelope.command.decode()

                    if command == Version.command.decode():
                        peer_version = Version.parse(envelope.stream())
                        logger.debug(
                            f"Peer {peer_id_str} version: {peer_version.version}, height: {peer_version.start_height}"
                        )

                        last_block = self.db.lastBlock()
                        our_height = last_block["Height"] if last_block else 0
                        if self.peer_handshake_status.get(peer_id_str) is None:
                            version_msg = Version(start_height=our_height)
                            self.send_message(conn, version_msg)
                        verack_msg = VerAck()
                        self.send_message(conn, verack_msg)
                        self.peer_handshake_status[peer_id_str] = {
                            "version_received": True,
                            "verack_received": False,
                        }

                        if peer_version.start_height > our_height:
                            logger.info(
                                f"Peer {peer_id_str} has a longer chain (height {peer_version.start_height} vs our {our_height}). Starting sync..."
                            )
                            self.start_sync(conn)
                        else:
                            logger.debug(
                                f"Peer {peer_id_str} is at height {peer_version.start_height} (our {our_height}). No sync needed from this peer"
                            )

                    elif command == VerAck.command.decode():
                        if (
                            peer_id_str in self.peer_handshake_status
                            and self.peer_handshake_status[peer_id_str][
                                "version_received"
                            ]
                        ):
                            self.peer_handshake_status[peer_id_str][
                                "verack_received"
                            ] = True
                            logger.debug(
                                f"Handshake complete with {peer_id_str}. Connection established."
                            )

                    elif command == GetHeaders.command.decode():
                        getheaders_msg = GetHeaders.parse(envelope.stream())
                        self.handle_getheaders(conn, getheaders_msg)

                    elif command == Headers.command.decode():
                        headers_msg = Headers.parse(envelope.stream())
                        self.handle_headers(conn, headers_msg)

                    elif command == Block.command.decode():
                        block_obj = Block.parse(envelope.stream())
                        self.handle_block(block_obj, origin_peer_socket=conn)

                    elif command == Inv.command.decode():
                        inv_msg = Inv.parse(envelope.stream())
                        self.handle_inv(conn, inv_msg)

                    elif command == GetData.command.decode():
                        getdata_msg = GetData.parse(envelope.stream())
                        self.handle_getdata(conn, getdata_msg)

                    elif command == Tx.command.decode():
                        tx_obj = Tx.parse(envelope.stream())
                        self.handle_tx(tx_obj, origin_peer_socket=conn)

                    elif command == GetAddr.command.decode():
                        known_peers = []
                        with self.peers_lock:
                            for peer_id in self.peers:
                                host, port_str = peer_id.rsplit(":", 1)
                                known_peers.append((host, int(port_str)))
                        addr_msg = Addr(known_peers)
                        self.send_message(conn, addr_msg)

                    elif command == Addr.command.decode():
                        addr_message = Addr.parse(envelope.stream())
                        for new_host, new_port in addr_message.addresses:
                            self.connect_to_peer(new_host, new_port)

                    elif command == Ping.command.decode():
                        ping_msg = Ping.parse(envelope.stream())
                        pong_msg = Pong(ping_msg.nonce)
                        self.send_message(conn, pong_msg)

                    elif command == Pong.command.decode():
                        pong_msg = Pong.parse(envelope.stream())

                except (RuntimeError, ValueError, IndexError, SyntaxError) as e:
                    logger.error(
                        f"Failed to parse message from {peer_id_str}: {e}. Discarding message",
                        exc_info=True,
                    )
                    continue

        except (IOError, ConnectionResetError, socket.timeout) as e:
            logger.warning(f"Connection lost with peer {peer_id_str}. Reason: {e}")
        except Exception as e:
            logger.error(f"An error occurred with peer {peer_id_str}. Error: {e}")
        finally:
            self.cleanup_peer_connection(peer_id_str, conn)

    def start_sync(self, conn):
        with self.sync_lock:
            if self.is_syncing:
                return
            self.is_syncing = True

        logger.debug("Starting blockchain synchronization...")
        last_block = self.db.lastBlock()

        if not last_block:
            from src.core.genesis import GENESIS_BLOCK_HASH

            start_block_hash = bytes.fromhex(GENESIS_BLOCK_HASH)
        else:
            start_block_hash = bytes.fromhex(last_block["BlockHeader"]["blockHash"])

        getheaders_msg = GetHeaders(start_block=start_block_hash)
        self.send_message(conn, getheaders_msg)

    def handle_getheaders(self, conn, getheaders_msg):
        logger.debug(
            f"Received getheaders request starting from {getheaders_msg.start_block.hex()}"
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
                header = Block.to_obj(block_data).BlockHeader
                headers_to_send.append(header)
                if len(headers_to_send) >= MAX_HEADERS_TO_SEND:
                    break

        if found_start:
            if headers_to_send:
                logger.info(f"Sending {len(headers_to_send)} headers to peer")
            else:
                logger.info("Peer is up-to-date")

            headers_msg = Headers(headers_to_send)
            self.send_message(conn, headers_msg)

        elif getheaders_msg.start_block.hex() == "00" * 32 and not all_blocks:
            logger.info("Peer asked from genesis, we have no blocks")
            headers_msg = Headers([])
            self.send_message(conn, headers_msg)

        else:
            logger.warning(
                f"GetHeaders start_block {getheaders_msg.start_block.hex()} not found in main chain"
            )

    def handle_headers(self, conn, headers_msg):
        if not headers_msg.headers:
            logger.info("Finished headers synchronization (peer sent empty list)")
            with self.sync_lock:
                self.is_syncing = False
            return

        logger.debug(f"Received {len(headers_msg.headers)} headers from peer")

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
                            f"Header validation failed: Discontinuity in chain"
                        )
                        return
                else:
                    logger.error(
                        f"Header validation failed: Discontinuity in peer's batch"
                    )
                    return

            if not check_pow(header):
                logger.error("Header validation failed: Invalid Proof of Work")
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
            self.send_message(conn, getdata_msg)

        if len(headers_msg.headers) == MAX_HEADERS_TO_SEND:
            if not last_valid_header:
                logger.debug("Reached max headers but have no last valid header")
                return
            new_start_block_hash_hex = last_valid_header.generateBlockHash()
            new_start_block_hash_bytes = bytes.fromhex(new_start_block_hash_hex)

            logger.debug(
                f"Received max headers ({MAX_HEADERS_TO_SEND}). Requesting next batch starting from {new_start_block_hash_hex}"
            )

            getheaders_msg = GetHeaders(start_block=new_start_block_hash_bytes)
            self.send_message(conn, getheaders_msg)

        else:
            logger.info(
                f"Received {len(headers_msg.headers)} headers, sync is complete"
            )
            with self.sync_lock:
                self.is_syncing = False

    def handle_inv(self, conn, inv_msg):
        items_to_get = []
        for item_type, item_hash in inv_msg.items:
            if item_type == INV_TYPE_TX:
                if item_hash.hex() not in self.mempool:
                    items_to_get.append((INV_TYPE_TX, item_hash))
            elif item_type == INV_TYPE_BLOCK:
                if not self.db.get_block(item_hash.hex()):
                    items_to_get.append((INV_TYPE_BLOCK, item_hash))

        if items_to_get:
            getdata_msg = GetData(items_to_get)
            self.send_message(conn, getdata_msg)

    def handle_getdata(self, conn, getdata_msg):
        for item_type, item_hash in getdata_msg.items:
            if item_type == INV_TYPE_TX:
                tx_id = item_hash.hex()
                if tx_id in self.mempool:
                    tx_obj = self.mempool[tx_id]
                    tx_msg = Tx(
                        tx_obj.version, tx_obj.tx_ins, tx_obj.tx_outs, tx_obj.locktime
                    )
                    self.send_message(conn, tx_msg)
            elif item_type == INV_TYPE_BLOCK:
                block_hash_hex = item_hash.hex()
                block_data = self.db.get_block(block_hash_hex)
                if block_data:
                    block_obj = Block.to_obj(block_data)
                    block_msg = Block(
                        block_obj.Height,
                        block_obj.Blocksize,
                        block_obj.BlockHeader,
                        block_obj.Txcount,
                        block_obj.Txs,
                    )
                    self.send_message(conn, block_msg)

    def handle_tx(self, tx_obj, origin_peer_socket=None):
        tx_id = tx_obj.id()
        if not self.chain_manager:
            logger.warning(f"ChainManager is not initialised. Tx {tx_id} rejected...")
            return
        try:
            tx_was_added = self.chain_manager.add_transaction_to_mempool(tx_obj)
            if tx_was_added:
                if self.is_syncing:
                    logger.info(
                        f"Tx {tx_id} added to mempool (IBD in progress, not broadcasting)"
                    )
                else:
                    logger.info(f"Tx {tx_id} added, broadcasting...")
                    self.broadcast_tx(tx_obj, origin_peer_socket)
        except Exception as e:
            logger.error(f"Error with tx {tx_id}: {e}")

    def handle_block(self, block_obj, origin_peer_socket=None):
        block_hash = block_obj.BlockHeader.generateBlockHash()
        logger.info(f"Received block {block_obj.Height} ({block_hash})")

        if self.incoming_blocks_queue is not None:
            self.incoming_blocks_queue.put(block_obj)
        else:
            logger.warning(
                "Incoming_blocks_queue not initialized in SyncManager. Block discarded"
            )

    def cleanup_peer_connection(self, peer_id, conn):
        if conn:
            conn.close()
        with self.peers_lock:
            if peer_id in self.peers:
                del self.peers[peer_id]
        if peer_id in self.peer_handshake_status:
            del self.peer_handshake_status[peer_id]
        logger.info(f"Connection with {peer_id} closed and cleaned up")

    def broadcast_inv(self, inv_msg, origin_peer_socket=None):
        with self.peers_lock:
            peers_sockets = list(self.peers.values())
        for peer_socket in peers_sockets:
            if peer_socket != origin_peer_socket:
                try:
                    self.send_message(peer_socket, inv_msg)
                except Exception:
                    pass

    def broadcast_tx(self, tx_obj, origin_peer_socket=None):
        if self.is_syncing:
            logger.info(f"Cannot broadcast tx for {tx_obj.id()}: IBD in progress...")
            return
        tx_hash = bytes.fromhex(tx_obj.id())
        inv_msg = Inv(items=[(INV_TYPE_TX, tx_hash)])
        logger.info(f"Broadcasting transaction {tx_obj.id()}")
        self.broadcast_inv(inv_msg, origin_peer_socket)

    def broadcast_block(self, block_obj, origin_peer_socket=None):
        if self.is_syncing:
            logger.info(
                f"Cannot broadcast block {block_obj.Height}: IBD in progress..."
            )
            return
        block_hash = bytes.fromhex(block_obj.BlockHeader.generateBlockHash())
        inv_msg = Inv(items=[(INV_TYPE_BLOCK, block_hash)])
        logger.info(f"Broadcasting block {block_obj.Height}")
        self.broadcast_inv(inv_msg, origin_peer_socket)
