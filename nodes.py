import operator
from dataclasses import dataclass, field
from functools import reduce
from typing import Optional

import merklelib

from address import BloomFilter, Address
from blockchain import OutputIndex, TxOutput, TxID, sha256_hash, BlockChain, BlockHeight, Block, InvalidBlock, \
    Transaction, BlockHeader, UnlockingScript, TxInput, LockingScript


class Miner:
    def __init__(self, headers: list[BlockHeader]):
        self.address: Address = Address(headers=headers)

    def create_coinbase_tx(self, receiver_pubkey, value, tx_type='p2pk'):
        """Create a coinbase transaction."""
        # we use our own private/public key for type checking, but anything is valid
        unlocking_script = UnlockingScript(self.address.private_key, self.address.pubkey)
        tx_input = TxInput(unlocking_script, UTXO(0, 0, 0))

        locking_script = LockingScript(receiver_pubkey, tx_type=tx_type)
        tx_output = TxOutput(value, locking_script)

        return Transaction([tx_input], [tx_output])

    def create_block(self, transactions: list[Transaction]) -> Block:
        """Create a new block from a list of transactions."""
        cb_tx: Transaction = self.create_coinbase_tx(self.address.pubkey, 50)
        if len(self.address.headers) == 0:
            assert (len(transactions) == 0)  # no possible non-coinbase transactions in genesis block
            return Block([cb_tx])

        return Block([cb_tx] + transactions, hash(self.address.headers[-1]))


@dataclass
class UTXOinBlock:
    block_height: int
    output_dict: dict[OutputIndex, TxOutput]


@dataclass
class UTXO:
    txid: TxID
    output_index: OutputIndex
    value: int = field(hash=False)
    pending: Optional[TxID] = field(default=None, init=False)  # store the txid of the spending tx

    def __hash__(self):
        return sha256_hash(reduce(operator.add, (self.txid.to_bytes(32, 'big'),
                                                 self.output_index.to_bytes(4, 'big'),
                                                 self.value.to_bytes(10, 'big'))))


class UTXOSet:
    """
    https://eprint.iacr.org/2017/1095.pdf
    _____________________________________

    Bitcoin Core 0.14 Format
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


    """

    def __init__(self, blockchain: BlockChain):
        self.height: BlockHeight = len(blockchain) - 1
        self._data: dict[TxID, UTXOinBlock] = dict()
        if self.height >= 0:
            for tx in blockchain[0]:
                self[hash(tx)] = UTXOinBlock(0, {i: txo for i, txo in enumerate(tx.outputs)})

            for block in blockchain[1:]:
                self.update(block)

    def update(self, block: Block):
        """Update the UTXO set with the transactions in the block."""
        if not self.only_spendable_input(block):
            raise InvalidBlock(block)

        self.height += 1

        for tx in block:
            if not tx.is_coinbase:
                for txi in tx.inputs:
                    del self[txi.prev_txid].output_dict[txi.output_index]
                    if len(self[txi.prev_txid].output_dict) == 0:
                        del self[txi.prev_txid]

            self[hash(tx)] = UTXOinBlock(self.height, {index: txo for index, txo in enumerate(tx.outputs)})

    def only_spendable_input(self, block: Block) -> bool:
        """Determine if all TxInput uses spendable TxOutput

        Conditions (only for non-coinbase)
        ----------
            - txo referenced by txi is in utxo_set
            - txi unlocking script unlocks locking script of referenced txi


        """
        for tx in filter(lambda b: not b.is_coinbase, block):
            for txi in tx.inputs:
                try:
                    tx_output_dict = self[txi.prev_txid].output_dict
                    prev_txo = tx_output_dict[txi.output_index]
                    if not prev_txo.locking_script.unlock(txi.unlocking_script):
                        return False
                except KeyError:
                    return False
        return True

    def no_overspend(self, block: Block) -> bool:
        """Return True if and only if no tx spends more output than the utxo it claims.

        This excludes the coinbase tx, which may spend up to a fixed amount
        without reference to utxo. See Transaction.is_coinbase


        """
        # Note: only for use after UTXO_set.only_spendable_input
        for tx in block:
            if not tx.is_coinbase:
                cash: int = 0
                for txi in tx.inputs:
                    tx_output_dict = self[txi.prev_txid].output_dict
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

    def __setitem__(self, txid: TxID, value: UTXOinBlock):
        self._data[txid] = value

    def __delitem__(self, txid: TxID):
        del self._data[txid]


@dataclass
class ProofData:
    block_height: BlockHeight
    tx: Transaction
    proof: merklelib.AuditProof


BloomResponseType = dict[TxID, ProofData]


class FullNode:
    def __init__(self, blockchain: BlockChain = None):
        self.blockchain: BlockChain = blockchain or BlockChain()
        self.UTXO_set: UTXOSet = UTXOSet(self.blockchain)

    def add_block(self, block: Block):
        self.UTXO_set.update(block)
        self.blockchain.add_block(block)

    def validate_block(self, block: Block) -> bool:
        """Validate a new block.

        Conditions:
            - the block has proof of work
            - the block is either the genesis block or it has the previous blocks header
            - the block does not contain the same utxo spent twice
            - there is at most one coinbase tx and it is valid
            - the block does not spend more than the utxo it claims
            - the block only spends output in the UTXO set for which it has the public key


        """
        if not block.header.has_proof_of_work():
            return False

        if len(self.blockchain) > 0 and not block.header.prev_block_hash == hash(self.blockchain[-1]):
            return False

        if not block.no_internal_double_spend() or not block.one_valid_coinbase():
            return False

        if not self.UTXO_set.no_overspend(block) or not self.UTXO_set.only_spendable_input(block):
            return False

        return True

    @staticmethod
    def filter_tx(tx: Transaction, bloom: BloomFilter) -> bool:
        """Return True if and only if tx is matches against the bloom filter"""
        if bloom.check(hash(tx)):
            return True

        if any(True for txi in tx.inputs if bloom.check(txi.pubkey)):
            return True

        if any(True for txo in tx.outputs if bloom.check(txo.pubkey)):
            return True

        return False

    def filter_block(self, height: BlockHeight, bloom: BloomFilter) -> BloomResponseType:
        """Filter a block for matches against a bloom filter"""
        response: BloomResponseType = dict()
        block = self.blockchain[height]
        for tx in filter(lambda tx: self.filter_tx(tx, bloom), block):
            proof = block.transactions_merkle.get_proof(tx)
            response[hash(tx)] = ProofData(block_height=height, tx=tx, proof=proof)

        return response
