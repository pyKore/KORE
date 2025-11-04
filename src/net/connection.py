import socket

from src.net.netparams import P2P_TIMEOUT
from src.net.protocol import NetworkEnvelope


class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ADDR = (self.host, self.port)

    def startServer(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(self.ADDR)
        self.server.listen()

    def connect(self, port, bindPort=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(P2P_TIMEOUT)

        if bindPort:
            self.socket.bind((self.host, port))

        self.socket.connect((self.host, self.port))
        return self.socket

    def acceptConnection(self):
        self.conn, self.addr = self.server.accept()
        self.conn.settimeout(P2P_TIMEOUT)
        self.stream = self.conn.makefile("rb", None)
        return self.conn, self.addr

    def closeConnection(self):
        self.socket.close()

    def send(self, message):
        envelope = NetworkEnvelope(message.command, message.serialize())
        self.socket.sendall(envelope.serialize())

    def read(self, stream_obj=None):
        stream_to_read = stream_obj if stream_obj is not None else self.stream
        if stream_to_read is None:
            raise ConnectionError("No stream available to read from")

        envelope = NetworkEnvelope.parse(stream_to_read)
        return envelope
