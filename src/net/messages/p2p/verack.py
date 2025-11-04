class VerAck:
    command = b"verack"

    def __init__(self):
        pass

    def serialize(self):
        return b""

    @classmethod
    def parse(cls, s):
        return cls()
