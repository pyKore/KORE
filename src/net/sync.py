import logging
import socket
import time
from threading import Lock, RLock, Thread

from src.core.database.BlockchainDB import BlockchainDB
from src.net.connection import Node
from src.net.messages.p2p import (
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
from src.net.netparams import MAX_PEERS, PING_INTERVAL
from src.net.protocol import NetworkEnvelope
from src.net.services.chain_service import ChainService
from src.net.services.peer_service import PeerService

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
        self.incoming_blocks_queue = incoming_blocks_queue

        self.db = BlockchainDB()

        self.peer_handshake_status = {}
        self.peers = {}
        self.peers_lock = RLock()

        self.last_ping_sent = {}
        self.sync_lock = Lock()
        self.is_syncing = False

        self.peer_service = PeerService(self, self.db, self.mempool, self.chain_manager)
        self.chain_service = ChainService(self, self.db, self.incoming_blocks_queue)

        self.message_handlers = {
            Version.command: self.peer_service.handle_version,
            VerAck.command: self.peer_service.handle_verack,
            GetAddr.command: self.peer_service.handle_getaddr,
            Addr.command: self.peer_service.handle_addr,
            Ping.command: self.peer_service.handle_ping,
            Pong.command: self.peer_service.handle_pong,
            Inv.command: self.peer_service.handle_inv,
            Tx.command: self.peer_service.handle_tx,
            GetHeaders.command: self.chain_service.handle_getheaders,
            Headers.command: self.chain_service.handle_headers,
            Block.command: self.chain_service.handle_block,
            GetData.command: self.handle_getdata_router,
        }

    def send_message(self, sock, message):
        try:
            envelope = NetworkEnvelope(message.command, message.serialize())
            sock.sendall(envelope.serialize())
        except (OSError, socket.error, ConnectionResetError) as e:
            logger.warning(f"Failed to send message: {e}")

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
                    handler = self.message_handlers.get(envelope.command)

                    if handler:
                        handler(conn, peer_id_str, envelope.stream())
                    else:
                        logger.warning(
                            f"P2P command not found from {peer_id_str}: {command}"
                        )

                except (RuntimeError, ValueError, IndexError, SyntaxError) as e:
                    logger.error(
                        f"Failed to parse message from {peer_id_str}: {e}. Discarding message",
                        exc_info=True,
                    )
                    continue  # Continuer à écouter les prochains messages

        except (IOError, ConnectionResetError, socket.timeout) as e:
            logger.warning(f"Connection lost with peer {peer_id_str}. Reason: {e}")
        except Exception as e:
            logger.error(
                f"An error occurred with peer {peer_id_str}. Error: {e}", exc_info=True
            )
        finally:
            self.cleanup_peer_connection(peer_id_str, conn)

    def handle_getdata_router(self, peer_socket, peer_id_str, payload_stream):
        getdata_msg = GetData.parse(payload_stream)

        for item_type, item_hash in getdata_msg.items:
            if item_type == INV_TYPE_TX:
                self.peer_service.handle_getdata_tx(peer_socket, item_hash)
            elif item_type == INV_TYPE_BLOCK:
                self.chain_service.handle_getdata_block(peer_socket, item_hash)
            else:
                logger.warning(
                    f"GetData request for unknown type {item_type} from {peer_id_str}"
                )

    def cleanup_peer_connection(self, peer_id, conn):
        if conn:
            conn.close()
        with self.peers_lock:
            if peer_id in self.peers:
                del self.peers[peer_id]
        if peer_id in self.peer_handshake_status:
            del self.peer_handshake_status[peer_id]
        if peer_id in self.last_ping_sent:
            del self.last_ping_sent[peer_id]
        logger.info(f"Connection with {peer_id} closed and cleaned up")

    def broadcast_inv(self, inv_msg, origin_peer_socket=None):
        logger.debug(f"Broadcasting Inv message to {len(self.peers)} peers")
        with self.peers_lock:
            peers_sockets = list(self.peers.values())
        for peer_socket in peers_sockets:
            if peer_socket != origin_peer_socket:
                try:
                    self.send_message(peer_socket, inv_msg)
                except Exception as e:
                    logger.warning(f"Failed to broadcast Inv: {e}")

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
