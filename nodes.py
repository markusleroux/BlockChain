import logging
import math
import operator
from dataclasses import dataclass, field
from functools import reduce
from typing import Optional, Union
import socket
import select
import pickle

import bitarray
import ecdsa

import merklelib
import mmh3

from blockchain import OutputIndex, TxOutput, TxID, sha256_hash, BlockChain, BlockHeight, Block, \
    Transaction, BlockHeader, UnlockingScript, TxInput, LockingScript


@dataclass
class ProofData:
    block_height: BlockHeight
    tx: Transaction
    proof: merklelib.AuditProof


BloomResponseType = dict[TxID, ProofData]


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


class Messaging:
    self.MAX_TCP_MSG_SIZE = 2048

    @staticmethod
    def send(sock, obj):
        sock.sendall(len(bs).to_bytes(4) + pickle.dumps(obj))

    @staticmethod
    def receive(sock):
        """Reconstruct object from pickle data recieved by stream.

        Notes:
        - must already be listening on sock
        - does not close socket

        """
        len_bytes = b''
        while len(len_bytes) < 4:
            len_bs += int.from_bytes(sock.recv(32))

        l = int.from_bytes(len_bs)
            
        received = 0
        pieces = []
        while i < len_bytes:
            pieces.append(sock.recv(min(self.MAX_TCP_MSG_SIZE, l - received)))
            if pieces[-1] == b'':
                raise RuntimeError()

            received += len(pieces[-1])

        return pickle.loads(b''.join(pieces))


HandlingFunction = Callable[[Socket], None]


class TCPServer(Messaging):
    @staticmethod
    def __serve(self, ports: dict[int, HandlingFunction], **options):
        """Use the handling functions to serve incoming tcp connections on specific ports.

        options
        -------
        blocking : bool (False)
            blocking or non-blocking sockets
        host : str ("")
            the host to bind to
        max_requests : int (5)


        """

        socks = dict()
        for port, f in ports.items():
            socks[port] = socket.socket()       # INET Streaming socket
            socks[port].setblocking(options.get(blocking, False))
            socks[port].bind((options.get(host, ""), port))
            socks[port].listen(options.get(max_requests, 5))

        while True:
            read, writes, errors = ports.values(), [], []
            notified_sockets = select.select(reads, writes, errors, options.get(timeout, 60))[0]
            for ns in notified_sockets:
                sock, addr = ns.accept()
                if ns in ports.keys():
                    ports[ns](sock)


class TCPClient(Messaging):
    @staticmethod
    def connect(port, addr):
        sock = socket.socket()
        sock.connect((addr, port))
        return sock

    @staticmethod
    def send_receive(port, addr, obj):
        TCPClient.connect(port, addr)
        Messaging.send(sock, bloom)
        response = Messaging.receive(sock)
        sock.close()
        return response


class SimplifiedPaymentVerification(TCPClient):
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

    def request_headers(self, addr):
        """Request missing headers using TCP and wait for a list of headers."""
        NotImplemented


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


class Miner(TCPClient, TCPServer):
    def __init__(self, headers: list[BlockHeader]):
        self.address: Address = Address(headers=headers)
        self.known_full_nodes = set()
        self.known_tx = []

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

    def broadcast_block(self, block):
        for addr, port in self.known_full_nodes:
            sock = Miner.connect(port, addr)
            Miner.send(sock, block)
            sock.close()

    def serve(self):
        ports = { 9092: self.handle_address,
                  9093: self.handle_new_blocks }
        options = dict()
        self.__serve(ports, options)

    def handle_address(self, sock):
        """Add a new transaction to the list of known transactions not included in the chain."""
        NotImplemented

    def handle_new_blocks(self, sock):
        """Listen for the addition of a new block to the blockchain.
        Triggers miner to stop mining current block.

        """
        NotImplemented


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

class FullNode(TCPServer):
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

    def serve(self):
        ports = { 9090: self.handle_miner,
                  9091: self.handle_address }
        options = dict()
        self.__serve(ports, options)

    def handle_address(self, sock):
        """Reconstruct bloom filter from stream and respond with proofs."""
        bloom = receive_all_pickle(sock)
        bloom_response = self.filter_block(len(self.blockchain) - 1, bloom)
        response_data = pickle.dumps(bloom_response)
        sock.send(response_data)
        sock.close()

    def handle_miner(self, sock):
        """Reconstruct block from stream and add block to blockchain if valid."""
        block = receive_all_pickle(sock)
        sock.close()
        if self.validate_block(block):
            self.add_block(block)

