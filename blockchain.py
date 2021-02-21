from __future__ import annotations  # type annotations in the future

import hashlib  # hash function
import itertools
import operator  # non-infix addition
import time  # timestamp
from dataclasses import dataclass, InitVar  # class magic
from functools import reduce  # fold
from typing import Sequence  # type hints

import ecdsa  # elliptic curve keys
import merklelib  # merkle tree

from nodes import UTXO

OutputIndex = int
TxID = int
HeaderHash = int
BlockHeight = int


def sha256_hash(item: bytes) -> int:
    """Helper function which constructs a (32-byte) hash from an iterable list of hashable items"""
    return int.from_bytes(hashlib.sha256(item).digest(), 'big')


@dataclass(frozen=True)
class LockingScript:
    pubkey: bytes
    tx_type: str = 'p2pk'

    def to_bytes(self) -> bytes:
        if self.tx_type == 'p2pk':
            return self.pubkey
        else:
            raise NotImplementedError

    def unlock(self, unlocking_script: UnlockingScript) -> bool:
        """Return True if and only if the unlocking script unlocks this locking script."""
        if unlocking_script.tx_type != self.tx_type:
            return False

        if self.tx_type == 'p2pk':
            return ecdsa.VerifyingKey.from_string(self.pubkey).verify(unlocking_script.signature, self.pubkey)
        else:
            raise NotImplementedError


@dataclass
class UnlockingScript:
    private_key: InitVar[ecdsa.SigningKey]  # InitVar is not stored
    pubkey: bytes
    tx_type: str = 'p2pk'

    def __post_init__(self, private_key):
        self.signature = private_key.sign(self.pubkey)

    def to_bytes(self) -> bytes:
        if self.tx_type == 'p2pk':
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
        return '({}) '.format(self.value) + str(self.pubkey)


@dataclass
class TxInput:
    unlocking_script: UnlockingScript
    utxo: InitVar[UTXO]

    def __post_init__(self, utxo: UTXO):
        """Get the txid and output_index from UTXO and discard UTXO"""
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
        return str(self.pubkey) + ' ({})'.format(self.value)


@dataclass
class Transaction:
    inputs: list[TxInput]
    outputs: list[TxOutput]

    @property
    def is_coinbase(self):
        """Return True if and only if this is a valid coinbase transaction.

        Conditions:
        ----------
            - there is exactly one input transaction
            - the previous txid in that input is 0
            - the output index in that input is 0
            - the value of the output is less than 50


        """
        return len(self.inputs) == 1 and self.inputs[0].prev_txid == 0 and \
            self.inputs[0].output_index == 0 and sum(o.value for o in self.outputs) <= 50

    def __str__(self):
        result = '-------------------------------------------------\n'
        non_coinbase_input = filter(lambda txi: txi.value > 0, self.inputs)
        max_length = max((len(str(i)) for i in non_coinbase_input), default=15) + 15
        result += 'Transaction: {}\n'.format(hash(self))
        result += '{0:{2}} | {1}\n'.format('Inputs', 'Outputs', max_length)
        result += '{0:{2}}   {1}\n'.format('------', '-------', max_length)
        for i, o in itertools.zip_longest(non_coinbase_input, self.outputs):
            result += '{0:{2}} | {1}\n'.format(str(i), str(o), max_length)

        return result + '-------------------------------------------------\n'

    def __hash__(self) -> TxID:
        # This is a really bad way to do this
        result = reduce(operator.add,
                        (hash(i).to_bytes(32, 'big') for i in itertools.chain(self.inputs, self.outputs)),
                        b'0')
        return sha256_hash(result)


class BlockHeader:
    def __init__(self, merkle_root_hash, prev_block_hash):
        self.merkle_root_hash = merkle_root_hash
        self.prev_block_hash: HeaderHash = prev_block_hash
        self.nonce: int = 0
        self.timestamp: int = int(time.time())

    def increment_nonce(self):
        self.nonce += 1

    def proof_of_work(self):
        """Increments the nonce until the block has proof of work."""
        while not self.has_proof_of_work():
            self.increment_nonce()

    @staticmethod
    def has_proof_of_work() -> bool:
        """Predicate to determine if a block has proof of work."""
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
        return 'Merkle_Root: {},\n'.format(self.merkle_root_hash) + \
               'Nonce: {},\n'.format(self.nonce) + \
               'Timestamp: {},\n'.format(self.timestamp) + \
               'Previous Block Hash: {}'.format(self.prev_block_hash)


class InvalidBlock(Exception):
    def __init__(self, block: Block):
        self.block = block
        self.block_hash = hash(block)
        self.message = 'Invalid block'
        super().__init__(self.message)

    def __str__(self):
        return f'{self.block_hash}: {self.message}'


class Block:
    def __init__(self, transactions: Sequence[Transaction], prev_block_hash=None):
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
        """Return True if/only if no utxo is spent twice in the block."""
        spent_utxo = set()
        for tx in self:
            for txi in tx.inputs:
                if (txi.prev_txid, txi.output_index) in spent_utxo:
                    return False
                spent_utxo.add((txi.prev_txid, txi.output_index))
        return True

    def one_valid_coinbase(self) -> bool:
        """Return True if/only if the block contains at most one coinbase and it is valid."""
        return sum(1 for tx in self if tx.is_coinbase) <= 1

    def _dump_tx(self, txid: TxID):
        raise NotImplementedError

    def __iter__(self):
        yield from self._transactions

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
        self._chain: list[Block] = list()

    def add_block(self, block: Block):
        """Add a block to the blockchain.

        Conditions
        ----------
            - has proof of work
            - previous block header field matches blockchain head or genesis block


        """
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
        return 'Blockchain:\n----------- \n' + '\n\n'.join(block.__str__() for block in self) + '\n------------\n'
