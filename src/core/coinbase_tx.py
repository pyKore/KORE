import json
import logging
import os

logger = logging.getLogger(__name__)

from src.chain.params import HALVING_INTERVAL, INITIAL_REWARD_KOR, REDUCTION_FACTOR
from src.core.transaction import Tx, TxIn, TxOut
from src.scripts.script import Script
from src.utils.config_loader import get_miner_wallet
from src.utils.serialization import bytes_needed, decode_base58, int_to_little_endian


def load_miner_info():
    try:
        wallet_name = get_miner_wallet()
        if not wallet_name:
            raise KeyError
        wallet_path = os.path.join("data", "wallets", f"{wallet_name}.json")
        with open(wallet_path, "r") as f:
            wallet_data = json.load(f)
        return str(wallet_data["privateKey"]), wallet_data["PublicAddress"]
    except (FileNotFoundError, KeyError) as e:
        logger.error(
            f"Could not load miner wallet '{wallet_name}', please check config.ini and wallet files"
        )
        return None, None


class CoinbaseTx:
    def __init__(self, BlockHeight):
        self.BlockHeight = BlockHeight
        self.privateKey, self.minerAddress = load_miner_info()

    def calculate_reward(self):
        reduction_periods = self.BlockHeight // HALVING_INTERVAL
        reward_float = INITIAL_REWARD_KOR * (REDUCTION_FACTOR**reduction_periods)
        return max(0, int(reward_float))

    def CoinbaseTransaction(self, fees):
        if not self.minerAddress:
            logger.critical(
                "Miner address not loaded, cannot create coinbase transaction"
            )
            return None
        tx_ins = [
            TxIn(
                prev_tx=b"\0" * 32,
                prev_index=0xFFFFFFFF,
                script_sig=Script(
                    [
                        int_to_little_endian(
                            self.BlockHeight, bytes_needed(self.BlockHeight)
                        )
                    ]
                ),
            )
        ]

        total_reward = self.calculate_reward() + fees
        target_h160 = decode_base58(self.minerAddress)
        target_script = Script.p2pkh_script(target_h160)
        tx_outs = [TxOut(amount=total_reward, script_pubkey=target_script)]

        coinBaseTx = Tx(1, tx_ins, tx_outs, 0)
        coinBaseTx.TxId = coinBaseTx.id()
        return coinBaseTx
