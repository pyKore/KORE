from src.core.chain.primitives.block import Block as BlockClass


class Block(BlockClass):
    command = b"block"
