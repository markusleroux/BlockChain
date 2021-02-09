#!/usr/bin/env python3

import time
import merklelib
import ecdsa
import hashlib


class Address:
    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate()

    def public_key(self):
        return self.private_key.verifying_key

    def sign(self, byte_string):
        return self.private_key.sign(byte_string)


class TxInput:
    def __init__(self, prev_tx, output_index, script_sig):
        self.prev_tx_hash = hash(prev_tx)
        self.output_index = output_index
        self.script_sig = script_sig

    def __hash__(self):
        pass


class TxOutput:
    def __init__(self, value, script_pub_key):
        self.value = value
        self.script_pub_key = script_pub_key

    def __hash__(self):
        pass


class Transaction:
    def __init__(self):
        self.inputs = []
        self.outputs = []

    def __hash__(self):
        m = hashlib.sha256()
        for io in self.inputs + self.outputs:
            m.update(hash(io))

        return m.digest()


class BlockHeader:
    def __init__(self, prev_block_hash, merkle_root_hash):
        self.merkle_root_hash = merkle_root_hash 
        self.nonce = 0
        self.prev_block_hash = prev_block_hash 
        self.timestamp = time.time()

    def increment_nonce(self):
        self.nonce += 1

    def proof_of_work(self):
        while not self.has_proof_of_work():
            self.increment_nonce()

    @staticmethod
    def has_proof_of_work(self):
        return int.from_bytes(hash(self)) < 10**7

    def __hash__(self):
        m = hashlib.sha256()
        for item in (self.merkle_root_hash, self.prev_block_hash, self.nonce_to_bytes(), self.timestamp.to_bytes()):
            m.update(item)

        return m.digest()

class Block:
    def __init__(self, prev_block_hash, transactions):
        self.transactions = merklelib.MerkleTree(transactions)
        self.header = BlockHeader(prev_block_hash, self.transactions.merkle_hash)
        self.header.proof_of_work()

    def __hash__(self):
        # The header contains the merkle root hash, which ensures that
        # this defines a unique hash for each block
        return hash(self.header)

class BlockChain:
    def __init__(self):
        self.chain = []

    def validate_block(self, block):
        last_block = self.chain[-1]
        pass

    def add_block(self, block):
        if not self.validate_block(block):
            return False

        self.chain.append(block)
