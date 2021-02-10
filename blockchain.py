#!/usr/bin/env python3

import time
import merklelib
import ecdsa
import hashlib


class Address:
    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate()
        self.UTXOs = dict()     # txid : MyUTXO(txid, output_index, value)

    class MyUTXO:
        def __init__(self, txid, output_index, value):
            self.txid = txid 
            self.output_index = output_index
            self.value = value
            self.pending = False

    def public_key(self):
        return self.private_key.verifying_key

    def sign(self, byte_string):
        return self.private_key.sign(byte_string)

    def p2pk_locking_script(self, receiver_pubkey):
        return receiver_pubkey

    def p2pk_unlocking_script(self, UTXO):
        return self.sign(self.public_key)

    def reset_pending_transactions(self):
        for UTXO in self.UTXOs.values():
            UTXO.pending = False

    def clear_pending_transactions(self):
        for UTXO in self.UTXOs.values():
            if UTXO.pending:
                del UTXOs[UTXO.txid]

    def gather_UTXOs(self, value):
        remaining_value = value
        gathered_UTXO = set()
        for UTXO in self.UTXOs.values():
            if remaining_value <= 0:
                break

            remaining_value -= UTXO.value
            gathered_UTXO.add(UTXO)

        if remaining_value > 0:
            raise ValueError("Insufficient funds")
            
        return (gathered_UTXO, abs(remaining_value))

    def generate_lock_unlock(self, tx_type = "p2pk"):
        if tx_type == "p2pk":
            locking_script = self.p2pk_locking_script
            unlocking_script = self.p2pk_unlocking_script

        return (unlocking_script, locking_script)

    def create_transaction(self, value, reciever_pubkey, tx_type = "p2pk"):
        unlock, lock = self.generate_lock_unlock(tx_type) 
        inputs, outputs = [], []

        (gathered_UTXO, extra_value) = self.gather_UTXOs(value)
        for UTXO in gathered_UTXO:
            UTXO.pending = True
            unlocking_script = unlock()
            inputs.append(TxInput(UTXO, unlocking_script))

        locking_script = lock(receiver_pubkey)
        locking_script_for_change = lock(self.public_key)

        outputs.append(TxOutput(value, locking_script))
        outputs.append(TxOutput(change, locking_script_for_change))

        return Transaction(inputs, outputs)

    def create_genesis(self, receiver_pubkey, tx_type = "p2pk"):
        _, lock = self.generate_lock_unlock(tx_type)        
        locking_script = lock(receiver_pubkey)
        return Transaction([], [TxOutput(50, locking_script)])


def iterable_hash(self, hashable_it):
    """Helper function which constructs a hash from an iterable list of hashable items"""
    m = hashlib.sha256()
    for item in hashable_it:
        m.update(item)

    return m.digest()


class TxInput:
    def __init__(self, UTXO, unlocking_script):
        self.prev_txid = UTXO.txid
        self.output_index = UTXO.output_index
        self.unlocking_script = unlocking_script

    def __hash__(self):
        return iterable_hash((self.prev_txid, self.output_index, self.unlocking_script))


class TxOutput:
    def __init__(self, value, locking_script):
        self.value = value
        self.locking_script = locking_script

    def __hash__(self):
        return iterable_hash((self.value.to_bytes(), self.locking_script))


class Transaction:
    def __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs

    def __hash__(self):
        return iterable_hash((hash(io) for io in self.inputs + self.outputs))


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
        return int.from_bytes(hash(self)) < 10 ** 7

    def __hash__(self):
        return iterable_hash(
            (
                self.merkle_root_hash,
                self.prev_block_hash,
                self.nonce._to_bytes(),
                self.timestamp.to_bytes(),
            )
        )


class Block:
    def __init__(self, prev_block_hash, transactions):
        self.transactions = transactions
        self.transactions_merkle = merklelib.MerkleTree(transactions)
        self.header = BlockHeader(prev_block_hash, self.transactions.merkle_hash)
        self.header.proof_of_work()

    def contains_txid(self, txid):
        return self.transactions_merkle.verify_leaf_inclusion(
            txid, self.transactions_merkle.get_proof(txid)
        )

    def dump_tx(self, txid):
        pass

    def __hash__(self):
        # The header contains the merkle root hash, which ensures that
        # this defines a unique hash for each block
        return hash(self.header)


class BlockChain:
    def __init__(self):
        self.chain = []

    def add_block(self, block):
        self.chain.append(block)

    def fits_blockchain_head(self, new_block):
        return (
            new_block.header.has_proof_of_work()
            and new_block.header.prev_block_hash == hash(self.head())
        )

    def head(self):
        return self.chain[-1]


class InvalidBlock(Exception):
    def __init__(self, block):
        self.block = block
        self.block_hash = hash(block)
        self.message = "Invalid block"

    def __str__(self):
        return f"{self.block_hash}: {self.message}"


class FullNode:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.build_UTXO_set()

    def build_UTXO_set(self):
        self.UTXO_set = self.init_UTXO_set()
        for block in self.blockchain.chain[1:]:
            self.update_UTXO_set(block)

    def update_UTXO_set(self, block):
        for tx in block.transactions:
            try:
                for tx_in in tx.inputs:
                    del UTXO_set[hash(tx_in)]

                for tx_out in tx.outputs:
                    UTXO_set[hash(tx_out)] = tx_out

            except KeyError:
                raise InvalidBlock(block)

    def init_UTXO_set():
        pass

    def validate_block(self, block):
        if not self.blockchain.fits_blockchain_head(block):
            return False

        for tx in block.transactions:
            if not self.validate_tx(tx):
                return False

        return True

    def validate_tx(self, tx):
        # Assumes the transaction is happening at the end of the current blockchain

        cash = 0
        # Verify all inputs have unlocking script for corresponding output locking script
        # Collect sum of UTXO value
        for txi in tx.inputs:
            # Check that the tx is in the UTXO_set
            if not txi.prev_txid in UTXO_set:
                return False

            # Verify that the unlocking script unlocks the locking script
            prev_txo = UTXO_set[txi.prev_txid].outputs[txi.output_index]
            if not p2pk_verify(prev_txo.locking_script, txi.unlocking_script):
                return False

            # Collect the value of the previous output as cash on hand
            cash += prev_txo.value

        # Verify the amount output by this transaction is less than cash on hand
        for txo in tx.outputs:
            cash -= txo.value

        return cash >= 0


class Miner:
    def __init__(self, blockchain):
        self.blockchain = blockchain

    def add_block(self, block):
        # Assumes the transactions on the block are valid
        # but checks that the headers are in order
        if not self.blockchain.fits_blockchain_head(block):
            raise InvalidBlock(block)

        self.blockchain.add_block(block)

    def create_block(self, transactions):
        return Block(self.blockchain.head(), transactions)
