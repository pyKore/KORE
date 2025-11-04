import time

from src.utils.serialization import int_to_little_endian, little_endian_to_int


class Ping:
    command = b"ping"

    def __init__(self, nonce=int(time.time())):
        self.nonce = nonce

    def serialize(self):
        return int_to_little_endian(self.nonce, 8)

    @classmethod
    def parse(cls, s):
        nonce = little_endian_to_int(s.read(8))
        return cls(nonce)
