import random
import time

from blockchain import Transaction, BlockHeader, Block
from nodes import FullNode, Miner
from address import Address


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
        """Add a new miner to the set of miners and add their address to the list of addresses."""
        miner = Miner(headers or list())
        self.addresses[hash(miner.address)] = miner.address
        self.miners.add(miner)

    def enqueue_tx(self, tx: Transaction):
        """Add a new transaction to the queue of transactions."""
        self.tx_queue.append(tx)

    def dequeue_txs(self, n: int):
        """Remove the first n transactions from the list of transactions."""
        self.tx_queue = self.tx_queue[n:]

    def simulate_trading_round(self, fp: float = 0.5):
        """Simulate a series of transactions between addresses."""
        for address in filter(lambda ad: ad.wealth > 0, self.addresses.values()):
            if random.random() < fp:
                # proportion of wealth to spend
                proportion = random.randrange(11) / 10

                # Choose some number of recipients to receive a part of the money
                # n_recipients = random.randrange(1, 3)
                n_recipients = 1
                for _ in range(n_recipients):
                    tx_value = int(address.wealth * proportion / n_recipients)
                    recipient = random.choice([ad for ad in self.addresses.values()
                                               if ad.pubkey != address.pubkey])
                    tx = address.create_transaction(tx_value, recipient.pubkey)
                    self.enqueue_tx(tx)

    def simulate_mining_round(self, block_size: int = 10) -> Block:
        """Simulate multiple miners competing to finish a block."""
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
        """Simulate block validation by full nodes."""
        # Full nodes which are able to verify add the block
        for fn in filter(lambda full_node: full_node.validate_block(block), self.full_nodes):
            fn.add_block(block)

        for address in self.addresses.values():
            address.headers.append(block.header)

        # temporary solution
        self.dequeue_txs(len(block._transactions))

    def simulate_query_round(self):
        """Simulate the communication between full nodes and addresses to verify payments."""
        for address in self.addresses.values():
            bloom = address.generate_bloom_filter()
            full_node = random.choice(list(self.full_nodes))
            bloom_response = full_node.filter_block(-1, bloom)
            address.process_proofs(bloom_response)

        print('\nWealth: ')
        print(','.join(str(address.wealth) for address in self.addresses.values()), end=' | ')
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
