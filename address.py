import logging
import math
from typing import Union

import bitarray
import ecdsa
import merklelib
import mmh3

from blockchain import TxID, BlockHeader, Transaction, UnlockingScript, TxInput, \
    LockingScript, TxOutput, sha256_hash
from nodes import UTXO, ProofData, BloomResponseType


class BloomFilter:
    """Bloom filters allow for efficient descriptions of subsets of transactions.
       https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki#filter-matching-algorithm
       https://eprint.iacr.org/2014/763.pdf

    Notes: (default) murmur hash is a 32 bit int
    """

    def __init__(self, max_items: int, fp: float = 0.1):
        self.max_items = max_items
        self.fp = fp
        self.size = self.get_size(max_items, fp)
        self.n_hashes = self.get_n_hashes(max_items, self.size)
        self.bitarray = bitarray.bitarray(self.size)

    def add(self, item: Union[TxID, bytes]):
        """Add an item (tx or pubkey) to the filter."""
        for i in range(self.n_hashes):
            # Index error?
            if isinstance(item, TxID):
                logging.info('Adding txid {} to bloom filter.'.format(str(item)))
                self.bitarray[self.filter_hash(item.to_bytes(32, 'big'), i)] = True
            else:
                logging.info('Adding pubkey {} to bloom filter.'.format(str(item)))
                self.bitarray[self.filter_hash(item, i)] = True

    def check(self, item: Union[TxID, bytes]) -> bool:
        """Check if an item is in the filter."""
        if isinstance(item, TxID):
            return all(self.bitarray[self.filter_hash(item.to_bytes(32, 'big'), i)] for i in range(self.n_hashes))
        else:
            return all(self.bitarray[self.filter_hash(item, i)] for i in range(self.n_hashes))

    def filter_hash(self, item: bytes, hash_index: int) -> int:
        # mod to ensure list index is in range (collisions are not so important)
        return mmh3.hash(item, hash_index, signed=False) % self.size - 1

    @staticmethod
    def get_n_hashes(number_of_items: int, filter_size: int) -> int:
        """The number of hash functions required for a filter of size filter_size with max_items elements.

        Arguments
        ---------
        number_of_items : int
            The number of elements which will be added
        filter_size : the size of the filter


        """
        return int(math.log(2) * filter_size / number_of_items)

    @staticmethod
    def get_size(number_of_items: int, fp: float) -> int:
        """Return the size of the filter necessary to ensure false positive rate fp.

        Arguments
        ---------
        number_of_items : int
            The number of elements which will be added
        fp : float
            The desired false positive threshold


        """
        return int(- number_of_items * math.log(fp) / math.log(2) ** 2) + 100


class SimplifiedPaymentVerification:
    def __init__(self, headers: list[BlockHeader] = None, txids: set[TxID] = None, pubkeys: set[bytes] = None):
        self.headers: list[BlockHeader] = headers or list()
        self.interesting_txids: set[TxID] = txids or set()
        self.interesting_pubkeys: set[bytes] = pubkeys or set()

    def generate_bloom_filter(self, fp: float = 0.1, extra_size: int = 0) -> BloomFilter:
        """Return a bloom filter describing the interesting txid and pubkeys.

        Arguments
        --------
        fp : float in (0, 1)
            The maximum false positive rate when queering the filter
        extra_size : int
            The number of additional txid the filter can hold and guarantee fp rate

        Return
        ------
        bloom : BloomFilter
            A bloom filter describing the interesting txid and pubkeys


        """
        bloom = BloomFilter(len(self.interesting_txids) + len(self.interesting_pubkeys) + extra_size, fp)
        for txid in self.interesting_txids:
            bloom.add(txid)

        for pubkey in self.interesting_pubkeys:
            bloom.add(pubkey)

        return bloom

    def check_proofs(self, proof_data: ProofData) -> bool:
        """Check a proof against the local version of the blockchain headers"""
        # Decode the merkle_root_hash before using with merklelib
        result = merklelib.verify_leaf_inclusion(proof_data.tx, proof_data.proof,
                                                 merklelib.Hasher(),
                                                 self.headers[proof_data.block_height].merkle_root_hash.decode())

        if not result:
            logging.info('Invalid proof for txid {}'.format(str(hash(proof_data.tx))))
        else:
            logging.info('Found valid proof for txid {}'.format(str(hash(proof_data.tx))))

        return result

    def clean_bloom_response(self, proofs: BloomResponseType) -> BloomResponseType:
        """Remove proofs which were sent due to false positives in the bloom filter"""
        interesting_proofs = set()
        for txid, proof_data in proofs.items():
            if txid in self.interesting_txids:
                logging.info('Found interesting txid {} in proof.'.format(str(txid)))
                interesting_proofs.add(txid)
                continue

            if any(True for txi in proof_data.tx.inputs if txi.pubkey in self.interesting_pubkeys):
                logging.info('Found interesting txid {} in proof.'.format(str(txid)))
                interesting_proofs.add(txid)
                continue

            if any(True for txo in proof_data.tx.outputs if txo.pubkey in self.interesting_pubkeys):
                logging.info('Found interesting txid {} in proof.'.format(str(txid)))
                interesting_proofs.add(txid)

        return {txid: proofs[txid] for txid in interesting_proofs}


class Address(SimplifiedPaymentVerification):
    def __init__(self, headers: list[BlockHeader] = None):
        self.private_key: ecdsa.SigningKey = ecdsa.SigningKey.generate()
        self._my_utxo: dict[TxID, UTXO] = dict()
        super().__init__(headers=headers, pubkeys={self.pubkey})
        logging.info('Address {}: created'.format(str(self.pubkey)))

    @property
    def wealth(self) -> int:
        """Return the total value of utxo which is not pending."""
        return sum(utxo.value for utxo in self._my_utxo.values() if not utxo.pending)

    @property
    def pending_txs(self) -> set[UTXO]:
        """Return all pending utxo."""
        return {utxo for utxo in self._my_utxo.values() if utxo.pending}

    @property
    def pubkey(self) -> bytes:
        return self.private_key.verifying_key.to_string(encoding='compressed')

    def _sign(self, byte_string: bytes):
        """Sign the byte_string with addresses private key."""
        return self.private_key.sign(byte_string)

    def _register_incoming_tx(self, tx: Transaction):
        """Add all utxo in tx attributes to self.pubkey to _my_utxo"""
        logging.info('Address {}: registering incoming txid {}'.format(str(self.pubkey), str(hash(tx))))
        for index, o in filter(lambda item: item[1].pubkey == self.pubkey, enumerate(tx.outputs)):
            self[hash(tx)] = UTXO(hash(tx), index, o.value)

    def _clear_outgoing_tx(self, txid: TxID):
        """Remove UTXO when NEXT transaction has cleared."""
        logging.info('Address {}: clearing txid {} from personal utxo set'.format(str(self.pubkey), str(txid)))
        marked = []
        for utxo in filter(lambda utxo: utxo.pending, self._my_utxo.values()):
            if utxo.pending == txid:
                marked.append(utxo.txid)

        for u_txid in marked:
            del self[u_txid]

    def _gather_utxos(self, value: int) -> tuple[set[UTXO], int]:
        """Get a set of UTXO with combined value greater than value."""
        remaining_value = value
        gathered_utxo = set()
        for utxo in filter(lambda utxo: not utxo.pending, self._my_utxo.values()):
            if remaining_value <= 0:
                break

            remaining_value -= utxo.value
            gathered_utxo.add(utxo)

        if remaining_value > 0:
            raise ValueError('Insufficient funds')

        return gathered_utxo, abs(remaining_value)

    def create_transaction(self, value: int, receiver_pubkey: bytes, tx_type: str = 'p2pk') -> Transaction:
        """Return a transaction sending value amount to receiver_pubkey address."""
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
            utxo.pending = hash(tx)

        logging.info('Address {}: created tx {} with value {} and receiver {}'.format(str(self.pubkey),
                                                                                      str(hash(tx)),
                                                                                      str(value),
                                                                                      str(receiver_pubkey)))

        return tx

    def process_proofs(self, proofs: BloomResponseType):
        """Update pending transactions and add new utxo in accordance with proofs
        sent from a full node.


        """
        for txid, proof_data in self.clean_bloom_response(proofs).items():
            if not self.check_proofs(proof_data):
                print('proof for txid {} invalid'.format(txid))
                continue

            for txi in proof_data.tx.inputs:
                if txi.pubkey == self.pubkey:
                    self._clear_outgoing_tx(txid)

            for txo in proof_data.tx.outputs:
                if txo.pubkey == self.pubkey:
                    self._register_incoming_tx(proof_data.tx)

    def __getitem__(self, key):
        return self._my_utxo[key]

    def __setitem__(self, key, value):
        self._my_utxo[key] = value

    def __delitem__(self, key):
        del self._my_utxo[key]

    def __hash__(self):
        return sha256_hash(self.pubkey)