from src.utils.serialization import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)

INV_TYPE_ERROR = 0
INV_TYPE_TX = 1
INV_TYPE_BLOCK = 2


class Inv:
    command = b"inv"

    def __init__(self, items):
        self.items = items

    def serialize(self):
        result = encode_varint(len(self.items))
        for item_type, item_hash in self.items:
            result += int_to_little_endian(item_type, 4)
            result += item_hash[::-1]
        return result

    @classmethod
    def parse(cls, s):
        count = read_varint(s)
        items = []
        for _ in range(count):
            item_type = little_endian_to_int(s.read(4))
            item_hash = s.read(32)[::-1]
            items.append((item_type, item_hash))
        return cls(items)
