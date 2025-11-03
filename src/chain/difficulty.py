import logging

from src.chain.params import (
    AVERAGE_MINE_TIME,
    MAX_TARGET,
    RESET_DIFFICULTY_AFTER_BLOCKS,
)
from src.core.genesis import GENESIS_BITS
from src.database.db_manager import BlockchainDB
from src.utils.serialization import bits_to_target, target_to_bits

logger = logging.getLogger(__name__)


def get_ancestor_at_height(db, tip_hash, target_height):
    current_hash = tip_hash
    current_block = db.get_block(current_hash)
    if not current_block:
        return None

    current_height = current_block["Height"]

    while current_height > target_height:
        current_hash = current_block["BlockHeader"]["prevBlockHash"]
        current_block = db.get_block(current_hash)
        if not current_block:
            return None
        current_height = current_block["Height"]

    return current_block


def calculate_new_bits(current_height):
    db = BlockchainDB()
    last_block = db.lastBlock()

    if not last_block:
        return GENESIS_BITS

    if current_height % RESET_DIFFICULTY_AFTER_BLOCKS != 0:
        return bytes.fromhex(last_block["BlockHeader"]["bits"])

    start_period_height = current_height - RESET_DIFFICULTY_AFTER_BLOCKS

    first_block_in_period = get_ancestor_at_height(
        db, last_block["BlockHeader"]["blockHash"], start_period_height
    )

    if not first_block_in_period:
        return bytes.fromhex(last_block["BlockHeader"]["bits"])

    time_diff = (
        last_block["BlockHeader"]["timestamp"]
        - first_block_in_period["BlockHeader"]["timestamp"]
    )

    if time_diff == 0:
        time_diff = 1

    target_time = AVERAGE_MINE_TIME
    if time_diff < target_time // 4:
        time_diff = target_time // 4
    if time_diff > target_time * 4:
        time_diff = target_time * 4

    last_target = bits_to_target(bytes.fromhex(last_block["BlockHeader"]["bits"]))
    new_target = int(last_target * (time_diff / target_time))
    new_target = min(new_target, MAX_TARGET)
    new_bits = target_to_bits(new_target)

    logger.debug(
        f"Difficulty readjusted at height {current_height}. Time diff: {time_diff}s (Target: {target_time}s). New bits: {new_bits.hex()}"
    )

    return new_bits
