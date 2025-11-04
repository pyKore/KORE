from io import BytesIO

from src.utils.crypto.crypto_hash import hash256
from src.utils.crypto.serialization import int_to_little_endian, little_endian_to_int

NETWORK_MAGIC = b"\xf9\xbe\xb4\xd9"


class NetworkEnvelope:
    def __init__(self, command, payload):
        if isinstance(command, str):
            command = command.encode("utf-8")
        self.command = command
        self.payload = payload
        self.magic = NETWORK_MAGIC

    @classmethod
    def parse(cls, s):
        magic = s.read(4)
        if not magic:
            raise IOError("Connection closed or no data received")
        if magic != NETWORK_MAGIC:
            raise RuntimeError(
                f"Magic is not right {magic.hex()} vs {NETWORK_MAGIC.hex()}"
            )

        command = s.read(12).strip(b"\x00")
        payload_len = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payload_len)

        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise IOError("Checksum does not match")

        return cls(command, payload)

    def serialize(self):
        result = self.magic
        result += self.command + b"\x00" * (12 - len(self.command))
        result += int_to_little_endian(len(self.payload), 4)
        result += hash256(self.payload)[:4]
        result += self.payload
        return result

    def stream(self):
        return BytesIO(self.payload)
