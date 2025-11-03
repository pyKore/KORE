from src.utils.serialization import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)


class Addr:
    command = b"addr"

    def __init__(self, addresses):
        self.addresses = addresses

    def serialize(self):
        result = encode_varint(len(self.addresses))
        for host, port in self.addresses:
            host_bytes = host.encode("utf-8")
            result += encode_varint(len(host_bytes))
            result += host_bytes
            result += int_to_little_endian(port, 4)
        return result

    @classmethod
    def parse(cls, s):
        num_addresses = read_varint(s)
        addresses = []
        for _ in range(num_addresses):
            host_len = read_varint(s)
            host = s.read(host_len).decode("utf-8")
            port = little_endian_to_int(s.read(4))
            addresses.append((host, port))
        return cls(addresses)
