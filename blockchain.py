#!/usr/bin/env python3

from __future__ import annotations                          # type annotations in the future
from typing import Sequence, Optional, Union                # type hints
from functools import reduce                                # fold
from dataclasses import dataclass, field, InitVar           # class magic
import operator                                             # non-infix addition
import time                                                 # timestamp
import random                                               # randomness in network control
import math                                                 # log and power
import hashlib                                              # hash function
import bitarray                                             # bloom filter
import mmh3                                                 # murmer hashes
import merklelib                                            # merkle tree
import ecdsa                                                # eliptic curve keys


TxID = int
HeaderHash = int


def sha256_hash(item: bytes) -> int:
    """Helper function which constructs a hash from an iterable list of hashable items"""
    return int.from_bytes(hashlib.sha256(item).digest(), 'big')


@dataclass
class LockingScript:
    pubkey: bytes
    tx_type: str = "p2pk"

    def to_bytes(self):
        if self.tx_type == "p2pk":
            return self.pubkey
        else:
            raise NotImplementedError

    def unlock(self, unlocking_script: UnlockingScript):
        if unlocking_script.tx_type != self.tx_type:
            return False

        if self.tx_type == "p2pk":
            return ecdsa.VerifyingKey.from_string(self.pubkey).verify(unlocking_script.signature, self.pubkey)
        else:
            raise NotImplementedError


@dataclass
class UnlockingScript:
    private_key: InitVar[ecdsa.SigningKey]      # InitVar is not stored
    pubkey: bytes
    tx_type: str = "p2pk"

    def __post_init__(self, private_key):
        self.signature = private_key.sign(self.pubkey)

    def to_bytes(self):
        if self.tx_type == "p2pk":
            return self.signature
        else:
            raise NotImplementedError


@dataclass
class TxOutput:
    value: float
    locking_script: LockingScript

    def __hash__(self):
        return sha256_hash(
            self.value.to_bytes(4, 'big') + self.locking_script.to_bytes())


@dataclass
class TxInput:
    unlocking_script: UnlockingScript
    utxo: InitVar[UTXO]

    def __post_init__(self, utxo: UTXO):
        '''Get the txid and output_index from UTXO and discard UTXO'''
        self.prev_txid: TxID = utxo.txid
        self.output_index: int = utxo.output_index

    def __hash__(self):
        return sha256_hash(
            reduce(operator.add, (self.prev_txid.to_bytes(4, 'big'),
                                  self.output_index.to_bytes(4, 'big'),
                                  self.unlocking_script.to_bytes())))


@dataclass
class Transaction:
    inputs: list[TxInput]
    outputs: list[TxOutput]
    is_coinbase: bool = False

    def __hash__(self) -> TxID:
        # This is a really bad way to do this
        result = reduce(operator.add, (hash(i).to_bytes(10, 'big') for i in self.inputs), b'0')
        result += reduce(operator.add, (hash(o).to_bytes(10, 'big') for o in self.outputs), b'0')
        return sha256_hash(result)


class BloomFilter:
    '''Bloom filters allow for efficient descriptions of subsets of transactions.

    https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#filter-matching-algorithm
    '''
    def __init__(self, N: int, P: float):
        self.N = N
        self.P = P
        self.size = self.get_size(N, P)
        self.n_hashes = self.get_n_hashes(N, self.size)
        self.bitarray = bitarray.bitarray(self.size)

    def add(self, item: Union[TxID, bytes]):
        '''Add an item (tx or pubkey) to the filter.'''
        for i in range(self.n_hashes):
            # Index error?
            self.bitarray[mmh3.hash(item, i)] = True

    def check(self, item: Union[TxID, bytes]) -> bool:
        '''Check if an item is in the filter.'''
        return all(self.bitarray(mmh3.hash(item, i)) for i in range(self.n_hashes))

    @staticmethod
    def get_size(N: int, P: float) -> int:
        '''Return the size of the filter necessary to ensure false positive rate P.

        Arguments
        ---------
        N : int
            The number of elements which will be added
        P : float
            The desired false positive threshold
        '''
        return int(((-1 / (math.log(2)**2)) * N * math.log(P)) / 8)

    @staticmethod
    def get_n_hashes(N: int, S: int) -> int:
        '''The number of hash functions required for a filter of size S with N elements.

        Arguments
        ---------
        N : int
            The number of elements which will be added
        S : the size of the filter
        '''
        return int(S * N * math.log(2) / 8)


BloomResponseType = dict[Union[TxID, bytes], tuple[int, Transaction, merklelib.AuditProof]]


class SimplifiedPaymentVerification:
    def __init__(self, headers: list[BlockHeader] = [], txids: set[TxID] = set(), pubkeys: set[bytes] = set()):
        self.headers = headers
        self.interesting_txids: set[TxID] = txids
        self.interesting_pubkeys: set[bytes] = pubkeys

    def add_header(self, header: BlockHeader):
        self.headers.append(header)

    def generate_bloom_filter(self, fp: float = 0.1, extra_size: int = 0) -> BloomFilter:
        '''Return a bloom filter describing the iteresting txid and pubkeys.

        Arguments
        --------
        fp : float in (0, 1)
            The maximum false positive rate when queering the filter
        extra_size : int
            The number of additional txid the filter can hold and guaruntee fp rate

        Return
        ------
        bloom : BloomFilter
            A bloom filter describing the interesting txid and pubkeys
        '''
        bloom = BloomFilter(len(self.interesting_txids) + len(self.interesting_pubkeys) + extra_size, fp)
        for txid in self.interesting_txids:
            bloom.add(txid)

        for pubkey in self.interesting_pubkeys:
            bloom.add(pubkey)

        return bloom

    def check_proofs(self, proofs: BloomResponseType, item: Union[TxID, bytes]) -> bool:
        '''Use the provided proofs to verify the inclusion of txid or pubkey in the chain.'''
        if isinstance(item, TxID):
            try:
                height, _, proof = proofs[item]
                prev_block_hash = self.headers[height].prev_block_hash
                return merklelib.verify_leaf_inclusion(item, proof, merklelib.Hasher(), prev_block_hash)
            except KeyError:
                print("Transaction not in collection of proofs.")
                return False

        elif isinstance(item, bytes):
            try:
                height, tx, proof = proofs[item]
                prev_block_hash = self.headers[height].prev_block_hash
                if not merklelib.verify_leaf_inclusion(hash(tx), proof, merklelib.Hasher(), prev_block_hash):
                    return False

                # AT LEAST one matching pubkey in tx
                return any(o.locking_script.pubkey == item for o in tx.outputs)

            except KeyError:
                print("Pubkey not in colection of proofs.")
                return False

@dataclass
class UTXO:
    txid: TxID
    output_index: int
    value: float = field(hash=False)
    _pending: Optional[TxID] = field(default=None, init=False)         # store the txid of the spending tx 


class Address(SimplifiedPaymentVerification):
    def __init__(self, headers: list[BlockHeader] = []):
        self.private_key: ecdsa.SigningKey = ecdsa.SigningKey.generate()
        self._my_utxo: dict[int, UTXO] = dict()  # txid : UTXO(txid, output_index, value)
        super().__init__(headers = headers, pubkeys = {self.public_key})

    @property
    def wealth(self) -> float:
        return sum(utxo.value for utxo in self._my_utxo.values() if utxo._pending)

    def has_pending(self) -> bool:
        return any(utxo._pending for utxo in self._my_utxo.values())

    def get_pending(self) -> set[UTXO]:
        return {utxo for utxo in self._my_utxo.values() if utxo._pending}

    @property
    def public_key(self) -> bytes:
        return self.private_key.verifying_key.to_string()

    def _sign(self, byte_string: bytes):
        return self.private_key.sign(byte_string)

    def _incoming_tx(self, tx: Transaction):
        '''Add all utxo in tx attributes to self.pubkey to _my_utxo'''
        for i, o in ((i, o) for i, o in enumerate(tx.outputs) if o.locking_script.pubkey == self.public_key):
            self[hash(tx)] = UTXO(hash(tx), i, o.value)

    def _reset_pending_transaction(self, txid: TxID):
        '''Reset UTXO when transaction has failed.'''
        self[txid]._pending = None

    def _clear_pending_tx(self, txid: TxID):
        '''Remove UTXO when transaction has cleared.'''
        del self._my_utxo[txid]
        self.interesting_txids.remove(txid)

    def _gather_utxos(self, value: float) -> tuple[set[UTXO], float]:
        '''Get a set of UTXO with combined value greater than value.'''
        remaining_value = value
        gathered_utxo = set()
        for utxo in filter(lambda utxo: not utxo._pending, self._my_utxo.values()):
            if remaining_value <= 0:
                break

            remaining_value -= utxo.value
            gathered_utxo.add(utxo)

        if remaining_value > 0:
            raise ValueError("Insufficient funds")

        return (gathered_utxo, abs(remaining_value))

    def create_transaction(self, value: float, receiver_pubkey: bytes, tx_type: str = "p2pk") -> Transaction:
        '''Return a transaction sending value amount to receiver_pubkey address.'''
        inputs, outputs = [], []

        (gathered_utxo, extra_value) = self._gather_utxos(value)
        for utxo in gathered_utxo:
            unlocking_script = UnlockingScript(self.private_key,
                                               self.public_key,
                                               tx_type=tx_type)
            inputs.append(TxInput(unlocking_script, utxo))

        locking_script = LockingScript(receiver_pubkey, tx_type=tx_type)
        locking_script_for_change = LockingScript(self.public_key,
                                                  tx_type=tx_type)

        outputs.append(TxOutput(value, locking_script))
        outputs.append(TxOutput(extra_value, locking_script_for_change))

        tx = Transaction(inputs, outputs)
        self.interesting_txids.add(hash(tx))
        for utxo in gathered_utxo:
            utxo._pending = hash(tx)

        return tx

    def create_genesis_tx(self, receiver_pubkey: bytes, tx_type: str = "p2pk"):
        '''Return a transaction sending 50 coin to receiver pubkey without using UTXO.'''
        locking_script = LockingScript(receiver_pubkey, tx_type=tx_type)
        tx = Transaction([], [TxOutput(50, locking_script)])
        self._incoming_tx(tx)
        return tx

    def process_proofs(self, proofs: BloomResponseType):
        for item in proofs.keys():
            if self.check_proofs(proofs, item):
                if isinstance(item, TxID):
                    try:
                        self._clear_pending_tx(item)
                    except KeyError:
                        # txid was interesting but not in my_utxo set
                        pass
                elif isinstance(item, bytes):
                    self._incoming_tx(proofs[item][1])

    def __getitem__(self, key):
        return self._my_utxo[key]

    def __setitem__(self, key, value):
        self._my_utxo[key] = value

    def __hash__(self):
        return sha256_hash(self.public_key)


class BlockHeader:
    def __init__(self, merkle_root_hash, prev_block_hash=None):
        self.merkle_root_hash = merkle_root_hash
        self.prev_block_hash: HeaderHash = prev_block_hash
        self.nonce: int = 0
        self.timestamp: int = int(time.time())

    def increment_nonce(self):
        self.nonce += 1

    def proof_of_work(self):
        '''Increments the nonce until the block has proof of work.'''
        while not self.has_proof_of_work():
            self.increment_nonce()

    @staticmethod
    def has_proof_of_work() -> bool:
        '''Predicate to determine if a block has proof of work.'''
        # return int.from_bytes(hash(self)) < 10 ** 7
        return True

    def __hash__(self) -> HeaderHash:
        result = reduce(operator.add, (self.merkle_root_hash,
                                       self.nonce.to_bytes(4, 'big'),
                                       self.timestamp.to_bytes(4, 'big')))

        if self.prev_block_hash:
            result += self.prev_block_hash.to_bytes(4, 'big')

        return sha256_hash(result)

    def __str__(self):
        return "Merkle_Root: {}, Nonce: {}, Timestamp: {}, Previous Block Hash: {}".format(self.merkle_root_hash,
                                                                                      self.nonce,
                                                                                      self.timestamp,
                                                                                      self.prev_block_hash)


class Block:
    def __init__(self, transactions: Sequence[Transaction], prev_block_hash=None):
        # better to store as dictionary
        self._transactions: list[Transaction] = list(transactions)
        self.transactions_merkle: merklelib.MerkleTree = merklelib.MerkleTree(transactions)
        self.header = BlockHeader(self.transactions_merkle.merkle_root.encode(), prev_block_hash)
        self.header.proof_of_work()

    def contains_txid(self, txid: TxID) -> bool:
        '''Verify tx specified by txid is contained in block.'''
        return self.transactions_merkle.verify_leaf_inclusion(txid, self.transactions_merkle.get_proof(txid))

    def __iter__(self):
        yield from self._transactions

    def _dump_tx(self, txid: TxID):
        pass

    def __getitem__(self, tx_number) -> Transaction:
        return self._transactions[tx_number]

    def __setitem__(self, tx_number, transaction):
        NotImplemented

    def __hash__(self) -> HeaderHash:
        # The header contains the merkle root hash, which ensures that
        # this defines a unique hash for each block
        return hash(self.header)

    def __str__(self):
        return self.header.__str__()


class BlockChain:
    def __init__(self):
        self._chain: list[Block] = []

    def add_block(self, block: Block):
        '''Add a block to the blockchain.

        Conditions
        ----------
            - has proof of work
            - previous block header field matches blockchain head or genesis block
        '''
        if block.header.has_proof_of_work():
            if len(self._chain) == 0:
                self._chain.append(block)
            elif len(self._chain) > 1 and block.header.prev_block_hash == hash(self[-1]):
                self._chain.append(block)

        raise InvalidBlock(block)

    def __len__(self):
        return len(self._chain)

    def __getitem__(self, height) -> Block:
        return self._chain[height]

    def __setitem__(self, height, block: Block):
        NotImplemented

    def __str__(self):
        return "\n".join(block.__str__() for block in self)


class InvalidBlock(Exception):
    def __init__(self, block: Block):
        self.block = block
        self.block_hash = hash(block)
        self.message = "Invalid block"
        super().__init__(self.message)

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
    def __init__(self, blockchain: BlockChain):
        self.height = len(blockchain)
        self._data: dict[int, tuple[int, dict[int, TxOutput]]] = dict()
        for tx in blockchain[0]:
            self[hash(tx)] = (0, dict(zip(range(len(tx.outputs)), tx.outputs)))

        for block in blockchain[1:]:
            self.update(block)

    def update(self, block: Block, new_height: int = -1):
        '''Update the UTXO set with the transactions in the block.'''
        if new_height < 0:
            new_height = self.height + 1

        for tx in block:
            for txi in tx.inputs:
                try:
                    del self._data[txi.prev_txid][1][txi.output_index]
                    if len(self[txi.prev_txid][1]) == 0:
                        del self._data[txi.prev_txid]
                except KeyError:
                    InvalidBlock(block)

            self[hash(tx)] = (new_height,
                              {index: txo for index, txo in enumerate(tx.outputs)})

        self.height = new_height

    def __getitem__(self, txid: TxID) -> tuple[int, dict[int, TxOutput]]:
        return self._data[txid]

    def __setitem__(self, txid: TxID, value: tuple[int, dict[int, TxOutput]]):
        self._data[txid] = value


class FullNode:
    def __init__(self, blockchain: BlockChain = BlockChain()):
        self.blockchain = blockchain
        self.UTXO_set = UTXOSet(blockchain)

    def add_block(self, block):
        self.UTXO_set.update(block)
        self.blockchain.add_block(block)

    def validate_block(self, block: Block) -> bool:
        '''Validate a new block.

        Conditions:
            - validate_tx(tx) holds for all tx in block
            - fits_blockchain_head(block) holds
            - no utxo is spent twice in block
        '''
        if not block.header.prev_block_hash == hash(self.blockchain[-1]):
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

    def validate_tx(self, tx: Transaction) -> bool:
        '''Validate a new transaction.

        Conditions:
            - all txi use txo in UTXOset
            - all txi contain correct unlocking script
            - total value of txo <= total value of txi
        '''
        cash: float = 0
        for txi in tx.inputs:
            try:
                prev_txo = self.UTXO_set[txi.prev_txid][1][txi.output_index]
            except KeyError:
                return False

            if not prev_txo.locking_script.unlock(txi.unlocking_script):
                return False

            cash += prev_txo.value

        for txo in tx.outputs:
            cash -= txo.value

        return cash >= 0

    def filter_block(self, height: int, bloom: BloomFilter) -> BloomResponseType:
        '''Filter a block for matches agains a bloom filter'''
        response: BloomResponseType = dict()
        block = self.blockchain[height]
        for tx in block:
            proof = block.transactions_merkle.get_proof(hash(tx))
            if bloom.check(hash(tx)):
                response[hash(tx)] = (height, tx, proof)

            for output in tx.outputs:
                pubkey = output.locking_script.pubkey
                if bloom.check(pubkey):
                    response[pubkey] = (height, tx, proof)

        return response


class Miner:
    def __init__(self, headers):
        self.address: Address = Address(headers=headers)

    def add_header(self, header: BlockHeader):
        '''Add a block to the local copy of the blockchain.'''
        self.address.add_header(header)

    def create_coinbase_tx(self, receiver_pubkey, value, tx_type = "p2pk"):
        # we use our own private/public key for type checking, but anything is valid
        unlocking_script = UnlockingScript(self.address.private_key, self.address.public_key, tx_type="p2pk")
        tx_input = TxInput(unlocking_script, UTXO(0, 0, value))

        locking_script = LockingScript(receiver_pubkey, tx_type = tx_type)
        tx_output = TxOutput(value, locking_script)

        return Transaction([tx_input], [tx_output], is_coinbase=True)

    def _create_block(self, transactions: Sequence[Transaction]) -> Block:
        '''Create a new block from a list of transactions.'''
        return Block(transactions, hash(self.address.headers[-1]))


class NetworkControl:
    def __init__(self, n_addresses: int, n_miners: int, n_full_nodes: int):
        self.addresses: dict[int, Address] = {
            hash(ad): ad for ad in (Address() for _ in range(n_addresses - n_miners))
        }

        self.miners: set[Miner] = set()
        for _ in range(n_miners):
            _ = self.add_miner()

        self.full_nodes: set[FullNode] = set()
        for _ in range(n_full_nodes):
            self.add_full_node(genesis_miner.blockchain)

        bloom = genesis_miner.address.generate_bloom_filter()
        full_node = random.choice(list(self.full_nodes))
        bloom_response = full_node.filter_block(0, bloom)
        genesis_miner.address.process_proofs(bloom_response)

        self.tx_queue: list[Transaction] = []

    def add_miner(self, headers: list[BlockHeader] = []):
        '''Add a new miner to the set of miners and add their address to the list of addresses.'''
        miner = Miner(headers)
        self.addresses[hash(miner.address)] = miner.address
        self.miners.add(miner)

    def add_full_node(self, blockchain: BlockChain):
        '''Add a new full node to the list of full nodes.'''
        self.full_nodes.add(FullNode(blockchain))

    def enqueue_tx(self, tx: Transaction):
        '''Add a new transaction to the queue of transactions.'''
        self.tx_queue.append(tx)

    def dequeue_txs(self, n: int):
        '''Remove the first n transactions from the list of transactions.'''
        self.tx_queue = self.tx_queue[n:]

    def simulate_trading_round(self, P: float = 1):
        '''Simulate a series of transactions between addresses.'''
        for address in self.addresses.values():
            if address.wealth > 0 and random.random() > P:
                # proportion of wealth to spend
                proportion = random.randrange(11) / 10

                # Choose some number of recipients to recieve a part of the money
                n_recipients = random.randrange(1, 6)
                for _ in range(n_recipients):
                    tx_value = address.wealth * proportion / n_recipients
                    recipient = random.choice([ad for ad in self.addresses.values()])
                    tx = address.create_transaction(tx_value, recipient.public_key)
                    self.enqueue_tx(tx)

        print(self.tx_queue)

    def simulate_mining_round(self, block_size = 10) -> Block:
        '''Simulate multiple miners competing to finish a block.'''
        best_time = None
        for miner in self.miners:
            start = time.time()
            block = miner._create_block(self.tx_queue[:block_size])
            end = time.time()
            elapsed = end - start
            if not best_time or elapsed < best_time:
                fastest_block, best_time = block, elapsed

        return fastest_block

    def simulate_verification_round(self, block: Block):
        '''Simulate block validation by full nodes.'''
        # Full nodes which are able to verify add the block
        for fn in filter(lambda fn: fn.validate_block(block), self.full_nodes):
            fn.add_block(block)

    def simulate_query_round(self):
        '''Simulate the communication between full nodes and addresses to verify payments.'''
        for address in self.addresses:
            bloom = address.generate_bloom_filter()
            full_node = random.choice(list(self.full_nodes))
            bloom_response = full_node.filter_block(full_node.blockchain[-1], bloom)
            address.process_proofs(bloom_response)

    def simulate_n_rounds(self, n_rounds):
        for _ in range(n_rounds):
            self.simulate_trading_round()
            block = self.simulate_mining_round()
            self.simulate_verification_round(block)
            self.simulate_query_round()


nc = NetworkControl(20, 2, 1)
nc.simulate_n_rounds(1)
