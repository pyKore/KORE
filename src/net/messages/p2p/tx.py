from src.core.txs.transaction import Tx as TxClass


class Tx(TxClass):
    command = b"tx"
