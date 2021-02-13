#!/usr/bin/env python3

import time
import math
import bitarray
import mmh3
import merklelib
import ecdsa
import hashlib


class Address:
    def __init__(self):
        self.private_key = ecdsa.signingKey.generate()
        self._myUTXOs = dict()  # txid : MyUTXO(txid, output_index, value)

    class MyUTXO:
        def __init__(self, txid, output_index, value):
            self.txid = txid
            self.output_index = output_index
            self.value = value
            self.pending = False

    @property
    def public_key(self):
        return self.private_key.verifying_key.to_string()

    def _sign(self, byte_string):
        return self.private_key.sign(byte_string)

    def generate_unlock_lock(self, tx_type="p2pk"):
        '''Return pair of unlocking and locking functions.'''
        if tx_type == "p2pk":
            return (self._p2pk_unlocking_script, self.__p2pk_locking_script)

    def _p2pk_locking_script(self, receiver_pubkey):
        return receiver_pubkey

    def _p2pk_unlocking_script(self):
        return self._sign(self.public_key)

    def _incoming_tx(self, txid, output_index, value):
        '''Add a transaction to myUTXO set'''
        self[txid] = self.MyUTXO(txid, output_index, value)

    def _reset_pending_transaction(self, txid):
        '''Reset UTXO when transaction has failed.'''
        self[txid].pending = False

    def _clear_pending_tx(self, txid):
        '''Remove UTXO when transaction has cleared.'''
        del self[txid]

    def _gather_UTXOs(self, value):
        '''Get a set of UTXO with combined value greater than value.'''
        remaining_value = value
        gathered_UTXO = set()
        for UTXO in self._myUTXOs.values():
            if remaining_value <= 0:
                break

            remaining_value -= UTXO.value
            gathered_UTXO.add(UTXO)

        if remaining_value > 0:
            raise ValueError("Insufficient funds")

        return (gathered_UTXO, abs(remaining_value))

    def create_transaction(self, value, receiver_pubkey, tx_type="p2pk"):
        '''Return a transaction sending value amount to receiver_pubkey address.'''
        unlock, lock = self.generate_unlock_lock(tx_type)
        inputs, outputs = [], []

        (gathered_UTXO, extra_value) = self._gather_UTXOs(value)
        for UTXO in gathered_UTXO:
            UTXO.pending = True
            unlocking_script = unlock()
            inputs.append(TxInput(UTXO, unlocking_script))

        locking_script = lock(receiver_pubkey)
        locking_script_for_change = lock(self.public_key)

        outputs.append(TxOutput(value, locking_script))
        outputs.append(TxOutput(extra_value, locking_script_for_change))

        return Transaction(inputs, outputs)

    def create_genesis_tx(self, receiver_pubkey, tx_type="p2pk"):
        '''Return a transaction sending 50 coin to receiver pubkey without using UTXO.'''
        _, lock = self.generate_unlock_lock(tx_type)
        locking_script = lock(receiver_pubkey)
        return Transaction([], [TxOutput(50, locking_script)])

    def __getitem__(self, txid):
        return self._myUTXOs[txid]

    def __setitem__(self, txid, utxo):
        self._myUTXOs[txid] = utxo

    def __key(self):
        return self.public_key

    def __hash__(self):
        return sha256_hash(self.__key())


class BloomFilter:
    '''Bloom filters allow for efficient descriptions of subsets of transactions.

    https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#filter-matching-algorithm
    '''
    def __init__(self, N, P):
        self.N = N
        self.P = P
        self.size = self.get_size(N, P)
        self.n_hashes = self.get_n_hashes(N, self.size)
        self.bitarray = bitarray.bitarray(self.size)

    def add(self, item):
        '''Add an item (usually, tx) to the filter.'''
        for i in range(self.n_hashes):
            # Index error?
            self.bitarray[mmh3.hash(item, i)] = True

    def check(self, item):
        '''Check if an item is in the filter.'''
        return any(self.bitarray(mmh3.hash(item, i)) for i in range(self.n_hashes))

    @staticmethod
    def get_size(N, P):
        '''Return the size of the filter necessary to ensure false positive rate P.

        Arguments
        ---------
        N : int
            The number of elements which will be added
        P : float
            The desired false positive threshold
        '''
        return int(((-1 / (math.log(2) ** 2)) * N * math.log(P)) / 8)

    @staticmethod
    def get_n_hashes(N, S):
        '''The number of hash functions required for a filter of size S with N elements.

        Arguments
        ---------
        N : int
            The number of elements which will be added
        S : the size of the filter
        '''
        return int(S * N * math.log(2) / 8)


class SimplifiedPaymentVerification:
    def __init__(self, headers):
        self.headers = headers

    def verify_tx(self, txid):
        NotImplemented


def sha256_hash(item):
    """Helper function which constructs a hash from an iterable list of hashable items"""
    m = hashlib.sha256()
    m.update(item)
    return int.from_bytes(m.digest(), "big")


class TxInput:
    def __init__(self, UTXO, unlocking_script):
        self.prev_txid = UTXO.txid
        self.output_index = UTXO.output_index
        self.unlocking_script = unlocking_script

    def __key(self):
        return (self.prev_txid, self.output_index, self.unlocking_script)

    def __hash__(self):
        return sha256_hash(self.__key())


class TxOutput:
    def __init__(self, value, locking_script):
        self.value = value
        self.locking_script = locking_script

    def __key(self):
        return (self.value.to_bytes(4, 'big'), self.locking_script)

    def __hash__(self):
        return sha256_hash(self.__key())


class Transaction:
    def __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs

    def __key(self):
        return tuple(io for io in self.inputs + self.outputs)

    def __hash__(self):
        return sha256_hash(self.__key())


class BlockHeader:
    def __init__(self, merkle_root_hash, prev_block_hash=None):
        self.merkle_root_hash = merkle_root_hash
        self.prev_block_hash = prev_block_hash
        self.nonce = 0
        self.timestamp = int(time.time())

    def increment_nonce(self):
        self.nonce += 1

    def proof_of_work(self):
        '''Increments the nonce until the block has proof of work.'''
        while not self.has_proof_of_work():
            self.increment_nonce()

    @staticmethod
    def has_proof_of_work():
        '''Predicate to determine if a block has proof of work.'''
        # return int.from_bytes(hash(self)) < 10 ** 7
        return True

    def __key(self):
        return (self.merkle_root_hash,
                self.nonce.to_bytes(4, 'big'),
                self.timestamp.to_bytes(4, 'big'),
                self.prev_block_hash)

    def __hash__(self):
        return sha256_hash(self.__key())

    def __str__(self):
        return "Merkle_Root: {}, Nonce: {}, Timestamp: {}, Previous Block Hash: {}".format(
            self.merkle_root_hash, self.nonce, self.timestamp, self.prev_block_hash)


class Block:
    def __init__(self, transactions, prev_block_hash=None):
        self._transactions = transactions
        self.transactions_merkle = merklelib.MerkleTree(transactions)
        self.header = BlockHeader(self.transactions_merkle.merkle_root.encode(), prev_block_hash)
        self.header.proof_of_work()

    def contains_txid(self, txid):
        '''Verify tx specified by txid is contained in block.'''
        return self.transactions_merkle.verify_leaf_inclusion(
            txid, self.transactions_merkle.get_proof(txid))

    def _dump_tx(self, txid):
        pass

    def __getitem__(self, tx_number):
        return self._transactions[tx_number]

    def __setitem__(self, tx_number):
        NotImplemented

    def __key(self):
        return self.header

    def __hash__(self):
        # The header contains the merkle root hash, which ensures that
        # this defines a unique hash for each block
        return hash(self.__key())

    def __str__(self):
        return self.header.__str__()


class BlockChain:
    def __init__(self, genesis_block):
        self._chain = [genesis_block]

    def add_block(self, block):
        '''Add a block to the blockchain.

        Conditions
        ----------
            - has proof of work
            - previous block header field matches blockchain head
        '''
        if (block.header.has_proof_of_work()
                and block.header.prev_block_hash == hash(self[-1])):
            self._chain.append(block)

        raise InvalidBlock(block)

    def __getitem__(self, height):
        return self._chain[height]

    def __setitem__(self, height, block):
        NotImplemented

    def __str__(self):
        return "\n".join(block.__str__() for block in self)


class InvalidBlock(Exception):
    def __init__(self, block):
        self.block = block
        self.block_hash = hash(block)
        self.message = "Invalid block"

    def __str__(self):
        return f"{self.block_hash}: {self.message}"


class UTXOSet:
    '''
    https://eprint.iacr.org/2017/1095.pdf
    _____________________________________

    Bitoin Core 0.14 Format
    key: value
    ----------
    key
        txid (hash(tx))
    value
        block height and [UTXO]


    Bitcoin Core 0.15 Format
    key: value == outpoint: coin
    ----------------------------
    key
        hash(tx) and output index

    value
        block height and value
    '''
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self._data = dict()
        for tx in blockchain[0]:
            self[hash(tx)] = (0, {index: txo for index, txo in enumerate(tx.outputs)})

        for block in self.blockchain[1:]:
            self.update(block)

    def update(self, block):
        '''Update the UTXO set with the transactions in the block.

        Notes: assumes the blockchain has not been updated.
        '''
        for tx in block:
            for txi in tx.inputs:
                try:
                    del self[txi.prev_txid][1][txi.output_index]
                    if len(self[txi.prev_txid][1]) == 0:
                        del self[txi.prev_txid]
                except KeyError:
                    InvalidBlock("Transaction not in UTXO set")

            self[hash(tx)] = (len(self.blockchain), {index: txo for index, txo in enumerate(tx.outputs)})

    def __getitem__(self, txid):
        return self._data[txid]

    def __setitem__(self, txid, value):
        self._data[txid] = value


class FullNode:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.UTXO_set = UTXOSet(blockchain)

    def validate_block(self, block):
        '''Validate a new block.

        Conditions:
            - validate_tx(tx) holds for all tx in block
            - fits_blockchain_head(block) holds
            - no utxo is spent twice in block
        '''
        if not self.blockchain.fits_blockchain_head(block):
            return False

        spent_utxo = set()
        for tx in block:
            for txi in tx.inputs:
                if (txi.prev_txid, txi.output_index) in spent_utxo:
                    return False
                spent_utxo.add((txi.prev_txid, txi.output_index))

            if not self.validate_tx(tx):
                return False

        return True

    def validate_tx(self, tx):
        '''Validate a new transaction.

        Conditions:
            - all txi use txo in UTXOset
            - all txi contain correct unlocking script
            - total value of txo <= total value of txi
        '''
        cash = 0
        for txi in tx.inputs:
            try:
                prev_txo = self.UTXO_set[txi.prev_txid][1][txi.output_index]
            except KeyError:
                return False

            if not self.verify_lock_unlock(prev_txo.locking_script,
                                           txi.unlocking_script):
                return False

            cash += prev_txo.value

        for txo in tx.outputs:
            cash -= txo.value

        return cash >= 0

    def verify_lock_unlock(self,
                           locking_script,
                           unlocking_script,
                           tx_type="p2pk"):
        '''Verify that the unlocking script unlocks the locking script.'''
        if tx_type == "p2pk":
            return ecdsa.signingKey.from_string(locking_script).verify(unlocking_script, locking_script)
        return True

    def filter_block(self, block, bloom_bitarray):
        NotImplemented

    def generate_proofs(self, block, txids):
        return [block.transactions_merkle.get_proof(txid) for txid in txids]


class Miner:
    def __init__(self, blockchain=None):
        self.address = Address()
        if not blockchain:
            # Create genesis_block
            genesis_tx = self.address.create_genesis_tx(
                self.address.public_key)
            self.blockchain = BlockChain(Block([genesis_tx]))
        else:
            self.blockchain = blockchain

    def add_block(self, block):
        '''Add a block to the local copy of the blockchain.'''
        self.blockchain.add_block(block)

    def _create_block(self, transactions):
        '''Create a new block from a list of transactions.'''
        return Block(transactions, hash(self.blockchain[-1]))


class NetworkControl:
    def __init__(self, n_miners, n_addresses, n_full_nodes):
        self.addresses = {hash(ad): ad for ad in (Address() for _ in range(n_addresses))}

        self.miners = set()
        genesis_miner = self.add_miner()
        for _ in range(n_miners):
            _ = self.add_miner(genesis_miner.blockchain)

        self.full_nodes = set()
        for _ in range(n_full_nodes):
            self.add_full_node(genesis_miner.blockchain)

        self.tx_queue = []

    def add_miner(self, blockchain=None):
        '''Add a new miner to the set of miners and add their address to the list of addresses.'''
        miner = Miner(blockchain)
        self.addresses[hash(miner.address)] = miner.address
        self.miners.add(miner)
        return miner

    def add_full_node(self, blockchain):
        '''Add a new full node to the list of full nodes.'''
        self.full_nodes.add(FullNode(blockchain))

    def enqueue_tx(self, tx):
        '''Add a new transaction to the queue of transactions.'''
        self.tx_queue.append(tx)

    def dequeue_txs(self, n):
        '''Remove the first n transactions from the list of transactions.'''
        self.tx_queue = self.tx_queue[n:]


'''
ad1, ad2 = Address(), Address()
genesis_block = Block([ad1.create_genesis_tx(ad2.public_key)])
bc = BlockChain(genesis_block)
print("Blockchain after genesis:")
print(bc)

ad1.clear_pending_transactions()
ad2._incoming_tx(genesis_block[0], 0)
miner = Miner(bc)
txs = [ad2.create_transaction(2, ad1.public_key) for _ in range(10)]
blk = miner._create_block(txs)
# print(blk)
miner.add_block(blk)
print("\n\nBlockchain after 2 blocks:")
print(bc)
'''
