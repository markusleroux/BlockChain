#!/usr/bin/env python3

from __future__ import annotations                          # type annotations in the future
from typing import Sequence, Optional, Union                # type hints
from collections import namedtuple
from functools import reduce                                # fold
from dataclasses import dataclass, field, InitVar           # class magic
import logging
import itertools
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
BlockHeight = int
OutputIndex = int


def sha256_hash(item: bytes) -> int:
    """Helper function which constructs a (32-byte) hash from an iterable list of hashable items"""
    return int.from_bytes(hashlib.sha256(item).digest(), 'big')


@dataclass(frozen = True)
class LockingScript:
    pubkey: bytes
    tx_type: str = "p2pk"

    def to_bytes(self) -> bytes:
        if self.tx_type == "p2pk":
            return self.pubkey
        else:
            raise NotImplementedError

    def unlock(self, unlocking_script: UnlockingScript) -> bool:
        '''Return True if and only if the unlocking script unlocks this locking script.'''
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

    def to_bytes(self) -> bytes:
        if self.tx_type == "p2pk":
            return self.signature
        else:
            raise NotImplementedError


@dataclass
class TxOutput:
    value: int
    locking_script: LockingScript

    @property
    def pubkey(self):
        return self.locking_script.pubkey

    def __hash__(self):
        return sha256_hash(
            self.value.to_bytes(4, 'big') + self.locking_script.to_bytes())

    def __str__(self):
        return "({}) ".format(self.value) + str(self.pubkey)


@dataclass
class TxInput:
    unlocking_script: UnlockingScript
    utxo: InitVar[UTXO]

    def __post_init__(self, utxo: UTXO):
        '''Get the txid and output_index from UTXO and discard UTXO'''
        self.prev_txid: TxID = utxo.txid
        self.output_index: OutputIndex = utxo.output_index
        self.value = utxo.value

    @property
    def pubkey(self):
        return self.unlocking_script.pubkey

    def __eq__(self, other):
        if isinstance(other, TxInput):
            return self.unlocking_script == other.unlocking_script and \
                self.prev_txid == other.prev_txid and \
                self.output_index == other.output_index
        else:
            return False

    def __hash__(self):
        return sha256_hash(
            reduce(operator.add, (self.prev_txid.to_bytes(32, 'big'),
                                  self.output_index.to_bytes(4, 'big'),
                                  self.unlocking_script.to_bytes())))

    def __str__(self):
        return str(self.pubkey) + " ({})".format(self.value)


@dataclass
class Transaction:
    inputs: list[TxInput]
    outputs: list[TxOutput]

    @property
    def is_coinbase(self):
        '''Return True if and only if this is a valid coinbase transaction.

        Conditions:
        ----------
            - there is exactly one input transaction
            - the previous txid in that input is 0
            - the output index in that input is 0
            - the value of the output is less than 50


        '''
        return len(self.inputs) == 1 and \
            self.inputs[0].prev_txid == 0 and \
            self.inputs[0].output_index == 0 and \
            sum(o.value for o in self.outputs) <= 50

    def __hash__(self) -> TxID:
        # This is a really bad way to do this
        result = reduce(operator.add, (hash(i).to_bytes(32, 'big') for i in self.inputs), b'0')
        result += reduce(operator.add, (hash(o).to_bytes(32, 'big') for o in self.outputs), b'0')
        return sha256_hash(result)

    def __str__(self):
        result = "-------------------------------------------------\n"
        non_coinbase_input = filter(lambda txi: txi.value > 0, self.inputs)
        max_length = max((len(str(i)) for i in non_coinbase_input), default = 15) + 15
        result += "Transaction: {}\n".format(hash(self))
        result += "{0:{2}} | {1}\n".format("Inputs", "Outputs", max_length)
        result += "{0:{2}}   {1}\n".format("------", "-------", max_length)
        for i, o in itertools.zip_longest(non_coinbase_input, self.outputs):
            result += "{0:{2}} | {1}\n".format(str(i), str(o), max_length)

        return result + "-------------------------------------------------\n"


class BloomFilter:
    '''Bloom filters allow for efficient descriptions of subsets of transactions.
       https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#filter-matching-algorithm
       https://eprint.iacr.org/2014/763.pdf

    Notes: (default) murmur hash is a 32 bit int
    '''
    def __init__(self, N: int, P: float = 0.1):
        self.N = N
        self.P = P
        self.size = self.get_size(N, P)
        self.n_hashes = self.get_n_hashes(N, self.size)
        self.bitarray = bitarray.bitarray(self.size)

    def add(self, item: Union[TxID, bytes]):
        '''Add an item (tx or pubkey) to the filter.'''
        for i in range(self.n_hashes):
            # Index error?
            if isinstance(item, TxID):
                logging.info('Adding txid {} to bloom filter.'.format(str(item)))
                self.bitarray[self.filter_hash(item.to_bytes(32, 'big'), i)] = True
            else:
                logging.info('Adding pubkey {} to bloom filter.'.format(str(item)))
                self.bitarray[self.filter_hash(item, i)] = True

    def filter_hash(self, item: bytes, hash_index: int) -> int:
        # mod to ensure list index is in range (colisions are not so important)
        return mmh3.hash(item, hash_index, signed = False) % self.size - 1

    def check(self, item: Union[TxID, bytes]) -> bool:
        '''Check if an item is in the filter.'''
        if isinstance(item, TxID):
            return all(self.bitarray[self.filter_hash(item.to_bytes(32, 'big'), i)] for i in range(self.n_hashes))
        else:
            return all(self.bitarray[self.filter_hash(item, i)] for i in range(self.n_hashes))

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
        return int(- N * math.log(P) / math.log(2)**2) + 100

    @staticmethod
    def get_n_hashes(N: int, S: int) -> int:
        '''The number of hash functions required for a filter of size S with N elements.

        Arguments
        ---------
        N : int
            The number of elements which will be added
        S : the size of the filter


        '''
        return int(math.log(2) * S / N)


TxWithProof = namedtuple('TxWithProof', 'block_height tx proof')
BloomResponseType = dict[TxID, TxWithProof]


class SimplifiedPaymentVerification:
    def __init__(self, headers: list[BlockHeader] = None, txids: set[TxID] = None, pubkeys: set[bytes] = None):
        self.headers: list[BlockHeader] = headers or list()
        self.interesting_txids: set[TxID] = txids or set()
        self.interesting_pubkeys: set[bytes] = pubkeys or set()

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

    def clean_bloom_response(self, proofs: BloomResponseType) -> BloomResponseType:
        '''Remove proofs which were sent due to false positives in the bloom filter'''
        interesting_proofs = set()
        for txid, (height, tx, proof) in proofs.items():
            if txid in self.interesting_txids:
                logging.info('Found interesting txid in proof.'.format(str(txid)))
                interesting_proofs.add(txid)
                continue

            if any(True for txi in tx.inputs if txi.pubkey in self.interesting_pubkeys):
                logging.info('Found interesting txid {} in proof.'.format(str(txid)))
                interesting_proofs.add(txid)
                continue

            if any(True for txo in tx.outputs if txo.pubkey in self.interesting_pubkeys):
                logging.info('Found interesting txid {} in proof.'.format(str(txid)))
                interesting_proofs.add(txid)

        return {txid: proofs[txid] for txid in interesting_proofs}

    def check_proofs(self, block_height: BlockHeight, tx: Transaction, proof: merklelib.AuditProof) -> bool:
        '''Check a proof against the local version of the blockchain headers'''
        # Decode the merkle_root_hash before using with merklelib
        result = merklelib.verify_leaf_inclusion(tx, proof,
                                            merklelib.Hasher(),
                                            self.headers[block_height].merkle_root_hash.decode())

        if not result:
            logging.info('Invalid proof for txid {}'.format(str(hash(tx))))
        else:
            logging.info('Found valid proof for txid {}'.format(str(hash(tx))))

        return merklelib.verify_leaf_inclusion(tx, proof,
                                            merklelib.Hasher(),
                                            self.headers[block_height].merkle_root_hash.decode())


@dataclass
class UTXO:
    txid: TxID
    output_index: OutputIndex
    value: int = field(hash=False)
    _pending: Optional[TxID] = field(default=None, init=False)         # store the txid of the spending tx

    def __hash__(self):
        return sha256_hash(reduce(operator.add, (self.txid.to_bytes(32, 'big'),
                                                self.output_index.to_bytes(4, 'big'),
                                                self.value.to_bytes(10, 'big'))))


class Address(SimplifiedPaymentVerification):
    def __init__(self, headers: list[BlockHeader] = None):
        self.private_key: ecdsa.SigningKey = ecdsa.SigningKey.generate()
        self._my_utxo: dict[TxID, UTXO] = dict()
        super().__init__(headers = headers, pubkeys = {self.pubkey})
        logging.info('Address {}: created'.format(str(self.pubkey)))

    @property
    def wealth(self) -> int:
        '''Return the total value of utxo which is not pending.'''
        return sum(utxo.value for utxo in self._my_utxo.values() if not utxo._pending)

    @property
    def pending_txs(self) -> set[UTXO]:
        '''Return all pending utxo'''
        return {utxo for utxo in self._my_utxo.values() if utxo._pending}

    @property
    def pubkey(self) -> bytes:
        return self.private_key.verifying_key.to_string(encoding='compressed')

    def _sign(self, byte_string: bytes):
        '''Sign the byte_string with addresses private key.'''
        return self.private_key.sign(byte_string)

    def _register_incoming_tx(self, tx: Transaction):
        '''Add all utxo in tx attributes to self.pubkey to _my_utxo'''
        logging.info('Address {}: registering incoming txid {}'.format(str(self.pubkey), str(hash(tx))))
        for index, o in filter(lambda item: item[1].pubkey == self.pubkey, enumerate(tx.outputs)):
            self[hash(tx)] = UTXO(hash(tx), index, o.value)

    def _clear_outgoing_tx(self, txid: TxID):
        '''Remove UTXO when NEXT transaction has cleared.'''
        logging.info('Address {}: clearing txid {} from personal utxo set'.format(str(self.pubkey), str(txid)))
        marked = []
        for utxo in filter(lambda utxo: utxo._pending, self._my_utxo.values()):
            if utxo._pending == txid:
                marked.append(utxo.txid)

        for utxid in marked:
            del self._my_utxo[utxid]

    def _gather_utxos(self, value: int) -> tuple[set[UTXO], int]:
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

    def create_transaction(self, value: int, receiver_pubkey: bytes, tx_type: str = "p2pk") -> Transaction:
        '''Return a transaction sending value amount to receiver_pubkey address.'''
        inputs, outputs = [], []

        (gathered_utxo, extra_value) = self._gather_utxos(value)
        for utxo in gathered_utxo:
            unlocking_script = UnlockingScript(self.private_key,
                                               self.pubkey,
                                               tx_type=tx_type)
            inputs.append(TxInput(unlocking_script, utxo))

        locking_script = LockingScript(receiver_pubkey, tx_type=tx_type)
        locking_script_for_change = LockingScript(self.pubkey,
                                                  tx_type=tx_type)

        outputs.append(TxOutput(value, locking_script))
        outputs.append(TxOutput(extra_value, locking_script_for_change))

        tx = Transaction(inputs, outputs)

        for utxo in gathered_utxo:
            utxo._pending = hash(tx)

        logging.info('Address {}: created tx {} with value {} and receiver {}'.format(str(self.pubkey),
                                                                                      str(hash(tx)),
                                                                                      str(value),
                                                                                      str(receiver_pubkey)))

        return tx

    def process_proofs(self, proofs: BloomResponseType):
        '''Update pending transactions and add new utxo in accordance with proofs
        sent from a full node.


        '''
        for txid, (block_height, tx, proof) in self.clean_bloom_response(proofs).items():
            if not self.check_proofs(block_height, tx, proof):
                print("proof for txid {} invalid".format(txid))
                continue

            for txi in tx.inputs:
                if txi.pubkey == self.pubkey:
                    self._clear_outgoing_tx(txid)

            for txo in tx.outputs:
                if txo.pubkey == self.pubkey:
                    self._register_incoming_tx(tx)

    def __getitem__(self, key):
        return self._my_utxo[key]

    def __setitem__(self, key, value):
        self._my_utxo[key] = value

    def __hash__(self):
        return sha256_hash(self.pubkey)


class BlockHeader:
    def __init__(self, merkle_root_hash, prev_block_hash):
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
                                       self.nonce.to_bytes(10, 'big'),
                                       self.timestamp.to_bytes(10, 'big'),
                                       self.prev_block_hash.to_bytes(32, 'big')))

        return sha256_hash(result)

    def __str__(self):
        # The style here is a little rough, but how to break up string...
        return "Merkle_Root: {},\n".format(self.merkle_root_hash) + \
        "Nonce: {},\n".format(self.nonce) + \
        "Timestamp: {},\n".format(self.timestamp) + \
        "Previous Block Hash: {}".format(self.prev_block_hash)


class InvalidBlock(Exception):
    def __init__(self, block: Block):
        self.block = block
        self.block_hash = hash(block)
        self.message = "Invalid block"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.block_hash}: {self.message}"


class Block:
    def __init__(self, transactions: Sequence[Transaction], prev_block_hash = None):
        self._transactions: list[Transaction] = list(transactions)
        self.transactions_merkle: merklelib.MerkleTree = merklelib.MerkleTree(transactions)

        if prev_block_hash is None and len(transactions) == 1 and transactions[0].is_coinbase:
            # Genesis block contains one tx and dummy prev_block_hash
            self.header = BlockHeader(self.transactions_merkle.merkle_root.encode(), 0)
        elif prev_block_hash is not None and len(transactions) >= 1:
            self.header = BlockHeader(self.transactions_merkle.merkle_root.encode(), prev_block_hash)
        else:
            raise ValueError

        self.header.proof_of_work()

    def no_internal_double_spend(self) -> bool:
        '''Return True if/only if no utxo is spent twice in the block.'''
        spent_utxo = set()
        for tx in self:
            for txi in tx.inputs:
                if (txi.prev_txid, txi.output_index) in spent_utxo:
                    return False
                spent_utxo.add((txi.prev_txid, txi.output_index))
        return True

    def one_valid_coinbase(self) -> bool:
        '''Return True if/only if the block contains at most one coinbase and it is valid.'''
        count = 0
        for coinbase in filter(lambda tx: tx.is_coinbase, self):
            if not coinbase.is_coinbase:
                return False
            count += 1
        return count <= 1

    def __iter__(self):
        yield from self._transactions

    def _dump_tx(self, txid: TxID):
        raise NotImplementedError

    def __getitem__(self, tx_number: int) -> Transaction:
        return self._transactions[tx_number]

    def __setitem__(self, tx_number, transaction: Transaction):
        raise NotImplementedError

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
                return None
            elif len(self._chain) > 0 and block.header.prev_block_hash == hash(self[-1]):
                self._chain.append(block)
                return None

        raise InvalidBlock(block)

    def __len__(self):
        return len(self._chain)

    def __getitem__(self, key) -> Block:
        return self._chain[key]

    def __setitem__(self, height: BlockHeight, block: Block):
        raise NotImplementedError

    def __str__(self):
        return "Blockchain:\n----------- \n" + "\n\n".join(block.__str__() for block in self) + '\n------------\n'


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
        self.height: BlockHeight = len(blockchain) - 1
        self._data: dict[TxID, tuple[BlockHeight, dict[OutputIndex, TxOutput]]] = dict()
        if self.height > 0:
            for tx in blockchain[0]:
                self[hash(tx)] = (0, dict(zip(range(len(tx.outputs)), tx.outputs)))

            for block in blockchain[1:]:
                self.update(block)

    def update(self, block: Block):
        '''Update the UTXO set with the transactions in the block.'''
        if not self.only_spendable_input(block):
            raise InvalidBlock(block)

        for tx in block:
            if not tx.is_coinbase:
                for txi in tx.inputs:
                    del self._data[txi.prev_txid][1][txi.output_index]
                    if len(self[txi.prev_txid][1]) == 0:
                        del self._data[txi.prev_txid]

            self[hash(tx)] = (self.height + 1,
                              {index: txo for index, txo in enumerate(tx.outputs)})

        self.height += 1

    def only_spendable_input(self, block: Block) -> bool:
        '''Determine if all TxInput uses spendable TxOutput

        Conditions (only for non-coinbase)
        ----------
            - txo referenced by txi is in utxo_set
            - txi unlocking script unlocks locking script of referenced txi


        '''
        for tx in filter(lambda b: not b.is_coinbase, block):
            for txi in tx.inputs:
                try:
                    tx_output_dict = self[txi.prev_txid][1]
                    prev_txo = tx_output_dict[txi.output_index]
                    if not prev_txo.locking_script.unlock(txi.unlocking_script):
                        return False
                except KeyError:
                    return False
        return True

    def no_overspend(self, block: Block) -> bool:
        '''Return True if and only if no tx spends more output than the utxo it claims.

        This exludes the coinbase tx, which may spend up to a fixed amount
        without reference to utxo. See Transaction.is_coinbase


        '''
        # Note: only for use after UTXO_set.only_spendable_input
        for tx in block:
            if not tx.is_coinbase:
                cash: int = 0
                for txi in tx.inputs:
                    tx_output_dict = self[txi.prev_txid][1]
                    utxo = tx_output_dict[txi.output_index]
                    cash += utxo.value

                if cash < sum(txo.value for txo in tx.outputs):
                    return False

            else:
                if sum(txo.value for txo in tx.outputs) > 50:
                    return False

        return True

    def __getitem__(self, item):
        return self._data[item]

    def __setitem__(self, txid: TxID, value: tuple[BlockHeight, dict[OutputIndex, TxOutput]]):
        self._data[txid] = value


class FullNode:
    def __init__(self, blockchain: BlockChain = None):
        self.blockchain: BlockChain = blockchain or BlockChain()
        self.UTXO_set: UTXOSet = UTXOSet(self.blockchain)

    def add_block(self, block: Block):
        self.UTXO_set.update(block)
        self.blockchain.add_block(block)

    def validate_block(self, block: Block) -> bool:
        '''Validate a new block.

        Conditions:
            - the block has proof of work
            - the block is either the genesis block or it has the previous blocks header
            - the block does not contain the same utxo spent twice
            - there is at most one coinbase tx and it is valid
            - the block does not spend more than the utxo it claims
            - the block only spends output in the UTXO set for which it has the public key


        '''
        if not block.header.has_proof_of_work():
            return False

        if len(self.blockchain) > 0 and not block.header.prev_block_hash == hash(self.blockchain[-1]):
            return False

        if not block.no_internal_double_spend() or not block.one_valid_coinbase():
            return False

        if not self.UTXO_set.no_overspend(block) or not self.UTXO_set.only_spendable_input(block):
            return False

        return True

    def filter_tx(self, tx: Transaction, bloom: BloomFilter) -> bool:
        '''Return True if and only if tx is matches against the bloom filter'''
        if bloom.check(hash(tx)):
            return True

        if any(True for txi in tx.inputs if bloom.check(txi.pubkey)):
            return True

        if any(True for txo in tx.outputs if bloom.check(txo.pubkey)):
            return True

        return False

    def filter_block(self, height: BlockHeight, bloom: BloomFilter) -> BloomResponseType:
        '''Filter a block for matches agains a bloom filter'''
        response: BloomResponseType = dict()
        block = self.blockchain[height]
        for tx in filter(lambda tx: self.filter_tx(tx, bloom), block):
            proof = block.transactions_merkle.get_proof(tx)
            response[hash(tx)] = TxWithProof(block_height = height, tx = tx, proof = proof)

        return response


class Miner:
    def __init__(self, headers: list[BlockHeader]):
        self.address: Address = Address(headers=headers)

    def create_coinbase_tx(self, receiver_pubkey, value, tx_type = "p2pk"):
        '''Create a coinbase transaction.'''
        # we use our own private/public key for type checking, but anything is valid
        unlocking_script = UnlockingScript(self.address.private_key, self.address.pubkey, tx_type="p2pk")
        tx_input = TxInput(unlocking_script, UTXO(0, 0, 0))

        locking_script = LockingScript(receiver_pubkey, tx_type = tx_type)
        tx_output = TxOutput(value, locking_script)

        return Transaction([tx_input], [tx_output])

    def create_block(self, transactions: list[Transaction]) -> Block:
        '''Create a new block from a list of transactions.'''
        cb_tx: Transaction = self.create_coinbase_tx(self.address.pubkey, 50)
        if len(self.address.headers) == 0:
            assert(len(transactions) == 0)      # no possible non-coinbase transactions in genesis block
            return Block([cb_tx], None)

        return Block([cb_tx] + transactions, hash(self.address.headers[-1]))


class NetworkControl:
    def __init__(self, n_addresses: int, n_miners: int, n_full_nodes: int):
        self.addresses: dict[int, Address] = {
            hash(ad): ad for ad in (Address() for _ in range(n_addresses - n_miners))
        }

        self.miners: set[Miner] = set()
        for _ in range(n_miners):
            self.add_miner()

        self.full_nodes: set[FullNode] = set((FullNode() for _ in range(n_full_nodes)))
        self.tx_queue: list[Transaction] = []

    def add_miner(self, headers: list[BlockHeader] = None):
        '''Add a new miner to the set of miners and add their address to the list of addresses.'''
        miner = Miner(headers or list())
        self.addresses[hash(miner.address)] = miner.address
        self.miners.add(miner)

    def enqueue_tx(self, tx: Transaction):
        '''Add a new transaction to the queue of transactions.'''
        self.tx_queue.append(tx)

    def dequeue_txs(self, n: int):
        '''Remove the first n transactions from the list of transactions.'''
        self.tx_queue = self.tx_queue[n:]

    def simulate_trading_round(self, P: float = 0.5):
        '''Simulate a series of transactions between addresses.'''
        for address in self.addresses.values():
            if address.wealth > 0 and random.random() < P:
                # proportion of wealth to spend
                proportion = random.randrange(11) / 10

                # Choose some number of recipients to recieve a part of the money
                # n_recipients = random.randrange(1, 3)
                n_recipients = 1
                for _ in range(n_recipients):
                    tx_value = int(address.wealth * proportion / n_recipients)
                    recipient = random.choice([ad for ad in self.addresses.values()
                                               if ad.pubkey != address.pubkey])
                    tx = address.create_transaction(tx_value, recipient.pubkey)
                    self.enqueue_tx(tx)

    def simulate_mining_round(self, block_size: int = 10) -> Block:
        '''Simulate multiple miners competing to finish a block.'''
        best_time = None
        for miner in self.miners:
            start = time.time()
            block = miner.create_block(self.tx_queue[:block_size])
            end = time.time()
            elapsed = end - start
            if not best_time or elapsed < best_time:
                fastest_block, best_time = block, elapsed

        # for tx in filter(lambda tx: tx.is_coinbase, fastest_block):
            # print('Coinbase {} created'.format(hash(tx)))

        return fastest_block

    def simulate_verification_round(self, block: Block):
        '''Simulate block validation by full nodes.'''
        # Full nodes which are able to verify add the block
        for fn in filter(lambda fn: fn.validate_block(block), self.full_nodes):
            fn.add_block(block)

        for address in self.addresses.values():
            address.headers.append(block.header)

        # temporary solution
        self.dequeue_txs(len(block._transactions))

    def simulate_query_round(self):
        '''Simulate the communication between full nodes and addresses to verify payments.'''
        for address in self.addresses.values():
            bloom = address.generate_bloom_filter()
            full_node = random.choice(list(self.full_nodes))
            bloom_response = full_node.filter_block(-1, bloom)
            address.process_proofs(bloom_response)

        print('\nWealth: ')
        print(','.join(str(address.wealth) for address in self.addresses.values()), end = ' | ')
        print(sum(address.wealth for address in self.addresses.values()))

    def simulate_n_rounds(self, n_rounds: int):
        print('\nInitial Round:')
        block = self.simulate_mining_round()
        self.simulate_verification_round(block)
        print(block[0])
        self.simulate_query_round()

        for iteration in range(n_rounds):
            print('\n-------------\nIteration: {}'.format(iteration))
            self.simulate_trading_round()
            block = self.simulate_mining_round()
            self.simulate_verification_round(block)
            self.simulate_query_round()


nc = NetworkControl(20, 5, 1)
nc.simulate_n_rounds(9)
