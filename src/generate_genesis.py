import json
import os
import sys
import time

sys.path.append(os.getcwd())

from src.core.block import Block
from src.core.blockheader import BlockHeader
from src.core.transaction import Tx, TxIn, TxOut
from src.scripts.script import Script
from src.utils.crypto_hash import hash256
from src.utils.serialization import little_endian_to_int, merkle_root, target_to_bits

GENESIS_REWARD_ADDRESS = "kY7G5zouz5BBxmBn2g5a6zCf7BGeW86eB1"
GENESIS_MESSAGE = b"Test"
INITIAL_TARGET = 0x0000FFFF00000000000000000000000000000000000000000000000000000000
TIMESTAMP = int(time.time())


def mine_genesis_block(block_header, target):
    nonce = 0
    current_hash_int = target + 1

    print("Mining Genesis Block...")
    while current_hash_int > target:
        nonce += 1
        block_header.nonce = nonce
        serialized_header = block_header.serialize()
        current_hash_bytes = hash256(serialized_header)
        current_hash_int = little_endian_to_int(current_hash_bytes)

        if nonce % 10000 == 0:
            print(f"Nonce: {nonce} | Hash: {current_hash_int:064x}", end="\r")

    print("\n\nGenesis Block Mined!")
    block_header.blockHash = current_hash_bytes[::-1].hex()
    return block_header


def main():
    tx_in = TxIn(prev_tx=b"\0" * 32, prev_index=0xFFFFFFFF)
    tx_in.script_sig.cmds.append(GENESIS_MESSAGE)

    from src.utils.serialization import decode_base58

    h160 = decode_base58(GENESIS_REWARD_ADDRESS)
    script_pubkey = Script.p2pkh_script(h160)
    tx_out = TxOut(amount=50 * 100000000, script_pubkey=script_pubkey)

    coinbase_tx = Tx(version=1, tx_ins=[tx_in], tx_outs=[tx_out], locktime=0)
    coinbase_tx.TxId = coinbase_tx.id()
    merkle_tree_root = merkle_root([bytes.fromhex(coinbase_tx.TxId)])
    bits = target_to_bits(INITIAL_TARGET)
    # bits = bytes.fromhex("3767021e")

    block_header = BlockHeader(
        version=1,
        prevBlockHash=b"\0" * 32,
        merkleRoot=merkle_tree_root,
        timestamp=TIMESTAMP,
        bits=bits,
        nonce=0,
    )

    mined_header = mine_genesis_block(block_header, INITIAL_TARGET)

    genesis_block = Block(
        Height=0,
        Blocksize=len(coinbase_tx.serialize()) + 80,
        BlockHeader=mined_header,
        TxCount=1,
        Txs=[coinbase_tx],
    )

    print("\n--- GENESIS BLOCK DATA ---")
    print(f"Timestamp: {mined_header.timestamp}")
    print(f"Bits: {mined_header.bits.hex()}")
    print(f"Nonce: {mined_header.nonce}")
    print(f"Merkle Root: {mined_header.merkleRoot.hex()}")
    print(f"Block Hash: {mined_header.blockHash}")
    print(f"Transaction Hash: {coinbase_tx.TxId}")
    print(f"Hash160: {h160.hex()}")

    print("\n=> Paste thoses infos in the  kmain/genesis.py file <=")


if __name__ == "__main__":
    main()
