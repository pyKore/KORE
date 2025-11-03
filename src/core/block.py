from src.core.blockheader import BlockHeader
from src.core.transaction import Tx
from src.utils.serialization import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)


class Block:
    command = b"block"

    def __init__(self, Height, Blocksize, BlockHeader, TxCount, Txs):
        self.Height = Height
        self.Blocksize = Blocksize
        self.BlockHeader = BlockHeader
        self.Txcount = TxCount
        self.Txs = Txs

    @classmethod
    def parse(cls, s):
        Height = little_endian_to_int(s.read(4))
        BlockSize = little_endian_to_int(s.read(4))
        blockHeader = BlockHeader.parse(s)
        numTxs = read_varint(s)
        Txs = []
        for _ in range(numTxs):
            tx = Tx.parse(s)
            setattr(tx, "TxId", tx.id())
            Txs.append(tx)
        return cls(Height, BlockSize, blockHeader, numTxs, Txs)

    def serialize(self):
        result = int_to_little_endian(self.Height, 4)
        result += int_to_little_endian(self.Blocksize, 4)
        result += self.BlockHeader.serialize()
        result += encode_varint(len(self.Txs))
        for tx in self.Txs:
            result += tx.serialize()
        return result

    @classmethod
    def to_obj(cls, block_dict):
        header_dict = block_dict["BlockHeader"]
        block_header = BlockHeader(
            header_dict["version"],
            bytes.fromhex(header_dict["prevBlockHash"]),
            bytes.fromhex(header_dict["merkleRoot"]),
            header_dict["timestamp"],
            bytes.fromhex(header_dict["bits"]),
            header_dict["nonce"],
        )
        block_header.blockHash = header_dict["blockHash"]

        Transactions = []
        for tx_dict in block_dict["Txs"]:
            tx_obj = Tx.to_obj(tx_dict)
            setattr(tx_obj, "TxId", tx_dict["TxId"])
            Transactions.append(tx_obj)

        return cls(
            block_dict["Height"],
            block_dict["Blocksize"],
            block_header,
            block_dict["TxCount"],
            Transactions,
        )

    def to_dict(self):
        self.BlockHeader.to_hex()
        self.BlockHeader = self.BlockHeader.__dict__
        self.Txs = [tx.to_dict() for tx in self.Txs]
        return self.__dict__
