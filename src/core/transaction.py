from src.scripts.script import Script
from src.utils.crypto_hash import hash256
from src.utils.serialization import (
    bytes_needed,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)

SIGHASH_ALL = 1


class Tx:
    command = b"Tx"

    def __init__(self, version, tx_ins, tx_outs, locktime):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime

    def id(self):
        return self.hash().hex()

    def hash(self):
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime)

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))

        for tx_in in self.tx_ins:
            result += tx_in.serialize()

        result += encode_varint(len(self.tx_outs))

        for tx_out in self.tx_outs:
            result += tx_out.serialize()

        result += int_to_little_endian(self.locktime, 4)
        return result

    def sigh_hash(self, input_index, script_pubkey):
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))

        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    script_sig=script_pubkey,
                    sequence=tx_in.sequence,
                ).serialize()
            else:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    script_sig=Script(),
                    sequence=tx_in.sequence,
                ).serialize()

        s += encode_varint(len(self.tx_outs))

        for tx_out in self.tx_outs:
            s += tx_out.serialize()

        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(s)
        return int.from_bytes(h256, "big")

    def sign_input(self, input_index, private_key, script_pubkey):
        z = self.sigh_hash(input_index, script_pubkey)
        z_bytes = z.to_bytes(32, "big")
        raw_sig_obj = private_key.ecdsa_sign(z_bytes)
        pub_key = private_key.pubkey
        der = pub_key.ecdsa_serialize(raw_sig_obj)
        sig = der + SIGHASH_ALL.to_bytes(1, "big")
        sec = private_key.pubkey.serialize(compressed=True)
        self.tx_ins[input_index].script_sig = Script([sig, sec])

    def verify_input(self, input_index, script_pubkey):
        tx_in = self.tx_ins[input_index]
        z = self.sigh_hash(input_index, script_pubkey)
        combined = tx_in.script_sig + script_pubkey
        return combined.evaluate(z)

    def is_coinbase(self):
        if len(self.tx_ins) != 1:
            return False
        first_input = self.tx_ins[0]
        if first_input.prev_tx != b"\x00" * 32:
            return False
        if first_input.prev_index != 0xFFFFFFFF:
            return False
        return True

    @classmethod
    def to_obj(cls, item):
        TxInList = []
        TxOutList = []

        for tx_in_data in item["tx_ins"]:
            cmds = []
            if "cmds" in tx_in_data["script_sig"]:
                for cmd in tx_in_data["script_sig"]["cmds"]:
                    if isinstance(cmd, int):
                        cmds.append(int_to_little_endian(cmd, bytes_needed(cmd)))
                    else:
                        cmds.append(bytes.fromhex(cmd))
            script_sig = Script(cmds)
            TxInList.append(
                TxIn(
                    bytes.fromhex(tx_in_data["prev_tx"]),
                    tx_in_data["prev_index"],
                    script_sig,
                )
            )

        for tx_out_data in item["tx_outs"]:
            cmdsout = []
            if "cmds" in tx_out_data["script_pubkey"]:
                for cmd in tx_out_data["script_pubkey"]["cmds"]:
                    if isinstance(cmd, int):
                        cmdsout.append(cmd)
                    else:
                        cmdsout.append(bytes.fromhex(cmd))
            script_pubkey = Script(cmdsout)
            TxOutList.append(TxOut(tx_out_data["amount"], script_pubkey))

        return cls(item["version"], TxInList, TxOutList, item["locktime"])

    def to_dict(self):
        result = self.__dict__.copy()
        result["TxId"] = self.id()
        result["tx_ins"] = []
        for tx_in in self.tx_ins:
            tx_in_dict = tx_in.__dict__.copy()
            tx_in_dict["prev_tx"] = tx_in.prev_tx.hex()

            script_sig_dict = tx_in.script_sig.__dict__.copy()
            cmds_hex = []
            for cmd in script_sig_dict["cmds"]:
                if isinstance(cmd, bytes):
                    cmds_hex.append(cmd.hex())
                else:
                    cmds_hex.append(cmd)
            script_sig_dict["cmds"] = cmds_hex
            tx_in_dict["script_sig"] = script_sig_dict

            result["tx_ins"].append(tx_in_dict)

        result["tx_outs"] = []
        for tx_out in self.tx_outs:
            tx_out_dict = tx_out.__dict__.copy()
            script_pubkey_dict = tx_out.script_pubkey.__dict__.copy()
            cmds_hex = []
            for cmd in script_pubkey_dict["cmds"]:
                if isinstance(cmd, bytes):
                    cmds_hex.append(cmd.hex())
                else:
                    cmds_hex.append(cmd)
            script_pubkey_dict["cmds"] = cmds_hex
            tx_out_dict["script_pubkey"] = script_pubkey_dict
            result["tx_outs"].append(tx_out_dict)

        return result


class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xFFFFFFFF):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def serialize(self):
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    @classmethod
    def parse(cls, s):
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def serialize(self):
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

    @classmethod
    def parse(cls, s):
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)

    def to_dict(self):
        """Creates a dictionary representation of the TxOut."""
        script_pubkey_dict = self.script_pubkey.__dict__.copy()
        cmds_hex = []
        for cmd in script_pubkey_dict["cmds"]:
            if isinstance(cmd, bytes):
                cmds_hex.append(cmd.hex())
            else:
                cmds_hex.append(cmd)
        script_pubkey_dict["cmds"] = cmds_hex
        return {
            "amount": self.amount,
            "script_pubkey": script_pubkey_dict,
        }

    @classmethod
    def from_dict(cls, data):
        """Creates a TxOut object from a dictionary."""
        cmdsout = []
        if "cmds" in data["script_pubkey"]:
            for cmd in data["script_pubkey"]["cmds"]:
                if isinstance(cmd, int):
                    cmdsout.append(cmd)
                else:
                    cmdsout.append(bytes.fromhex(cmd))
        script_pubkey = Script(cmdsout)
        return cls(data["amount"], script_pubkey)
