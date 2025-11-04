import logging
import time

logger = logging.getLogger(__name__)

from secp256k1 import PrivateKey

from src.core.chain.chainparams import KOR, TX_BASE_SIZE, TX_INPUT_SIZE, TX_OUTPUT_SIZE
from src.core.database.AccountDB import AccountDB
from src.core.txs.transaction import Tx, TxIn, TxOut
from src.scripts.script import Script
from src.utils.crypto.serialization import decode_base58


class Send:
    def __init__(self, fromAccount, toAccount, Amount_float, feeRate, UTXOS, MEMPOOL):
        self.FromPublicAddress = fromAccount
        self.toAccount = toAccount
        self.feeRate = feeRate
        self.receivedTime = time.time()
        self.utxos = UTXOS
        self.mempool = MEMPOOL
        self.isBalanceEnough = True

        if isinstance(Amount_float, (int, float)) and Amount_float > 0:
            self.Amount = int(Amount_float * KOR)
        else:
            self.Amount = 0
            self.isBalanceEnough = False
            logger.error(f"Invalid amount ({Amount_float}) passed to send")

    def estimate_tx_size(self, num_inputs, num_outputs):
        return (
            TX_BASE_SIZE + (num_inputs * TX_INPUT_SIZE) + (num_outputs * TX_OUTPUT_SIZE)
        )

    def scriptPubKey(self, PublicAddress):
        h160 = decode_base58(PublicAddress)
        script_pubkey = Script().p2pkh_script(h160)
        return script_pubkey

    def getPrivateKey(self):
        AllAccounts = AccountDB().get_all_wallets()
        if not AllAccounts:
            logger.error("Could not read accounts")
            return None
        for account in AllAccounts:
            if account.get("PublicAddress") == self.FromPublicAddress:
                return account.get("privateKey")
        logger.error(f"Private key not found for address {self.FromPublicAddress}")
        return None

    def prepareTxIn(self):
        TxIns = []
        self.Total = 0

        try:
            self.From_address_script_pubkey = self.scriptPubKey(self.FromPublicAddress)
            self.fromPubKeyHash = self.From_address_script_pubkey.cmds[2]
        except Exception as e:
            logger.error(f"Error creating scriptPubKey for sender: {e}")
            self.isBalanceEnough = False
            return []

        mempool_spent_utxos = set()
        current_mempool = dict(self.mempool)
        logger.debug(
            f"Checking {len(current_mempool)} transactions in mempool for spent UTXOs"
        )
        for tx_mem_obj in current_mempool.values():
            if hasattr(tx_mem_obj, "tx_ins"):
                for tx_in_mem in tx_mem_obj.tx_ins:
                    mempool_spent_utxos.add(
                        f"{tx_in_mem.prev_tx.hex()}_{tx_in_mem.prev_index}"
                    )
        logger.debug(f"Found {len(mempool_spent_utxos)} UTXOs spent in mempool")

        spendable_utxos = []
        confirmed_utxos = dict(self.utxos)
        for key, txout in confirmed_utxos.items():
            if key in mempool_spent_utxos:
                continue

            if (
                hasattr(txout.script_pubkey, "cmds")
                and len(txout.script_pubkey.cmds) > 2
                and txout.script_pubkey.cmds[2] == self.fromPubKeyHash
            ):
                try:
                    tx_hex, index_str = key.split("_")
                    index = int(index_str)
                    spendable_utxos.append(
                        {"tx_hex": tx_hex, "index": index, "amount": txout.amount}
                    )
                except (ValueError, IndexError):
                    logger.warning(f"Could not parse UTXO key {key}")
                    continue

        if not spendable_utxos:
            logger.warning("No spendable UTXOs found")
            self.isBalanceEnough = False
            return []

        spendable_utxos.sort(key=lambda x: x["amount"])

        for utxo in spendable_utxos:
            TxIns.append(TxIn(bytes.fromhex(utxo["tx_hex"]), utxo["index"]))
            self.Total += utxo["amount"]
            logger.debug(
                f"Selecting UTXO {utxo['tx_hex']}_{utxo['index']} with amount {utxo['amount']}. Total collected: {self.Total}"
            )

            estimated_size = self.estimate_tx_size(num_inputs=len(TxIns), num_outputs=2)
            estimated_fee = int(estimated_size * self.feeRate)

            if self.Total >= self.Amount + estimated_fee:
                logger.debug("Collected enough to cover amount + fees")
                break

        final_size = self.estimate_tx_size(num_inputs=len(TxIns), num_outputs=2)
        final_fee = int(final_size * self.feeRate)
        if self.Total < self.Amount + final_fee:
            self.isBalanceEnough = False
            return []

        self.isBalanceEnough = True
        return TxIns

    def prepareTxOut(self):
        TxOuts = []
        amount_to_send_kores = self.Amount

        num_outputs = 2  # 2 for now (receiver & sender)
        estimated_size = self.estimate_tx_size(
            num_inputs=len(self.TxIns), num_outputs=num_outputs
        )
        self.fee = int(estimated_size * self.feeRate)

        if self.Total < amount_to_send_kores + self.fee:
            logger.warning(
                f"Insufficient funds for amount + fee: Required {amount_to_send_kores + self.fee}, Available {self.Total}"
            )
            self.isBalanceEnough = False
            return []

        try:
            to_scriptPubkey = self.scriptPubKey(self.toAccount)
            TxOuts.append(TxOut(amount_to_send_kores, to_scriptPubkey))
        except Exception as e:
            logger.error(f"Error creating scriptPubKey for receiver: {e}")
            return []

        self.changeAmount = self.Total - amount_to_send_kores - self.fee

        if self.changeAmount > 0:
            if hasattr(self, "From_address_script_pubkey"):
                TxOuts.append(TxOut(self.changeAmount, self.From_address_script_pubkey))
            else:
                logger.error("Sender scriptPubKey not available for change output")

        elif self.changeAmount == 0:
            num_outputs = 1

        else:
            logger.error("Negative change amount calculated")
            return []

        final_size = self.estimate_tx_size(
            num_inputs=len(self.TxIns), num_outputs=num_outputs
        )
        self.fee = int(final_size * self.feeRate)

        return TxOuts

    def signTx(self):
        secret = self.getPrivateKey()
        if secret is None:
            logger.error("Cannot sign transaction without private key")
            return False

        try:
            secret_bytes = int(secret).to_bytes(32, "big")
            priv = PrivateKey(privkey=secret_bytes)
        except Exception as e:
            logger.error(f"Error creating PrivateKey object: {e}")
            return False

        if not hasattr(self, "From_address_script_pubkey"):
            logger.error("Sender scriptPubKey not defined, cannot sign")
            return False

        logger.debug(f"Signing transaction {self.TxObj.id()}...")
        for index, tx_in in enumerate(self.TxIns):
            logger.debug(
                f"Signing input #{index} spending UTXO {tx_in.prev_tx.hex()}:{tx_in.prev_index}"
            )
            try:
                self.TxObj.sign_input(index, priv, self.From_address_script_pubkey)
            except Exception as e:
                logger.error(f"Error signing input {index}: {e}")
                return False
        logger.debug("Transaction signing complete")
        return True

    def prepareTransaction(self):
        self.isBalanceEnough = True
        self.TxIns = self.prepareTxIn()
        if not self.isBalanceEnough:
            logger.warning(
                "Transaction preparation failed in prepareTxIn (Insufficient funds or UTXO unavailable)"
            )
            return False  #

        # Check for amount + fees
        self.TxOuts = self.prepareTxOut()
        if not self.isBalanceEnough:
            logger.warning(
                "Transaction preparation failed in prepareTxOut (Insufficient funds for fee)"
            )
            return False

        if not self.TxIns or not self.TxOuts:
            logger.warning("Transaction preparation failed (TxIns or TxOuts missing)")
            return False

        self.TxObj = Tx(1, self.TxIns, self.TxOuts, 0)
        self.TxObj.fee = self.fee
        self.TxObj.receivedTime = self.receivedTime

        # Signature
        if not self.signTx():
            logger.warning("Transaction preparation failed due to signing error")
            return False

        self.TxObj.TxId = self.TxObj.id()
        logger.info(f"Transaction prepared successfully: {self.TxObj.TxId}")
        return self.TxObj
