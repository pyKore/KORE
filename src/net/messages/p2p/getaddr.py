class GetAddr:
    command = b"getaddr"

    def serialize(self):
        return b""

    @classmethod
    def parse(cls, stream):
        return cls()
