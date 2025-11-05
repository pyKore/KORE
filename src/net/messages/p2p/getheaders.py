class GetHeaders:
    command = b"getheaders"

    def __init__(self, start_block, end_block=None):
        self.start_block = start_block
        self.end_block = end_block or (b"\x00" * 32)

    def serialize(self):
        # Can add serialize of hash_count and version
        result = self.start_block[::-1]
        result += self.end_block[::-1]
        return result

    @classmethod
    def parse(cls, s):
        start_block = s.read(32)[::-1]
        end_block = s.read(32)[::-1]
        return cls(start_block, end_block)
