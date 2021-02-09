#!/usr/bin/env python3

import time
import merklelib
import ecdsa
import hashlib


class Address:
    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate()
        self.UTXOs = []  # (txid, value, output index)

    def public_key(self):
        return self.private_key.verifying_key

    def sign(self, byte_string):
        return self.private_key.sign(byte_string)

    def create_locking_script(self, receiver_pubkey):
        return receiver_pubkey

    def create_unlocking_script(self, UTXO):
        return self.sign(self.public_key) 

    def gather_UTXOs(self, value):
        i, remaining_value = 0, value
        while remaining_value > 0:
            if i >= len(self.UTXOs):
                raise ValueError("Insufficient funds") 

            remaining_value -= self.UTXOs[i][1]
            i += 1

        return (i, abs(remaining_value))

    def create_transaction(self, value, reciever_pubkey):
        inputs, outputs = [], []

        (i, change) = self.gather_UTXOs(value)
        for UTXO in UTXOs[:i]: 
            unlocking_script = self.create_unlocking_script()
            inputs.append(TxInput(UTXO, unlocking_script))
            
        locking_script, locking_script_for_change = self.create_locking_script(receiver_pubkey), self.create_locking_script(self.public_key)
        outputs.append(TxOutput(value, locking_script))
        outputs.append(TxOutput(change, locking_script_for_change))

        return (Transaction(inputs, outputs), i)

def iterable_hash(self, hashable_it):
    '''Helper function which constructs a hash from an iterable list of hashable items'''
    m = hashlib.sha256()
    for item in hashable_it:
        m.update(item)

    return m.digest()
    
class TxInput:
    def __init__(self, UTXO, unlocking_script):
        self.prev_txid = UTXO[0] 
        self.output_index = UTXO[2]
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
        return int.from_bytes(hash(self)) < 10**7

    def __hash__(self):
        return iterable_hash((self.merkle_root_hash, self.prev_block_hash, self.nonce._to_bytes(), self.timestamp.to_bytes()))


class Block:
    def __init__(self, prev_block_hash, transactions):
        self.transactions = transactions
        self.transactions_merkle = merklelib.MerkleTree(transactions)
        self.header = BlockHeader(prev_block_hash, self.transactions.merkle_hash)
        self.header.proof_of_work()

    def contains_txid(self, txid):
        return self.transactions_merkle.verify_leaf_inclusion(txid, self.transactions_merkle.get_proof(txid))

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


class Miner:
    def __init__(self, blockchain = BlockChain()):
        self.blockchain = blockchain
        self.block_hash_to_index = dict()
        self.UTXO_set = dict()

    def get_block_by_hash(block_hash):
        return self.blockchain.chain[self.block_hash_to_index[block_hash]]

    def validate_block(self, block):
        if not block.header.prev_block_hash == hash(self.blockchain.chain[-1]) or block.header.has_proof_of_work():
            return False

        for tx in block.transactions:
            if not validate_tx(tx):
                return False

        return True

    def add_block(self, block):
        if not validate_block(block):
            raise ValueError("Invalid block")
        
        self.blockchain.add_block(block)
        self.block_hash_to_index[hash(block)] = len(self.chain)
        self.update_UTXO_set(block)

    def update_UTXO_set(self, block):
        for tx in block.transactions:
            for tx_in in tx.inputs:
                del UTXO_set[hash(tx_in)]

            for tx_out in tx.outputs:
                UTXO_set[hash(tx_out)] = (tx_out, hash(block))
        
    def validate_tx(self, tx):
        cash = 0
        # Verify all inputs have unlocking script for corresponding output locking script
        # Collect sum of UTXO value
        for tx_in in tx.inputs:
            try:
                # Check that the tx is in the block
                self.get_block_by_hash(self.UTXO_set[hash(tx)][1]).contains_txid(hash(tx))
                
                old_tx_out = self.UTXO_set[tx_in.prev_txid][0].outputs[tx_in.output_index]
                if not p2pk_verify(old_tx_out.locking_script, tx_in.unlocking_script):
                    return False
                
            except KeyError:
                return False

        # Verify the amount in output is less than cash on hand
        for tx_out in tx.outputs:
            cash -= tx_out.value

        return cash >= 0
            
