from src.core.blockheader import BlockHeader
from src.utils.serialization import encode_varint, read_varint


class Headers:
    command = b"headers"

    def __init__(self, headers):
        self.headers = headers

    def serialize(self):
        result = encode_varint(len(self.headers))
        for header in self.headers:
            result += header.serialize()
            # Bitcoin add a varint(0) for transactions numbers
        return result

    @classmethod
    def parse(cls, s):
        num_headers = read_varint(s)
        headers = []
        for _ in range(num_headers):
            headers.append(BlockHeader.parse(s))
            # read varint(0)
        return cls(headers)
