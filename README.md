# BlockChain
A toy model of Bitcoin for educational purposes. I wrote this blockchain to better my own understanding of the Bitcoin protocol; it is currently a 
work in progress. At present, the various components are able to function as a unit, and may be used to simulate the operation of Bitcoin using the
NetworkControl class. NetworkControl is round based and uses variables to pass data between nodes.

## Overview
Many of the core components of the Bitcoin protocol are included:
- Hashcash proof of work
- Block verification by full nodes uses the UTXO set
- Transaction information is requested by simplified payment verification nodes using bloom filters
- Full nodes respond to requests for transaction verification using merkle tree proofs
- Transactions are structured as lists of inputs and outputs, and miners receive payment through coinbase

That being said, there are also a number of simplifications and deviations from the protocol:
- Only the pay-to-public-key (p2pk) transaction type is available
- Hash functions do not match those used in Bitcoin, and the current implementation uses a naive method to serialize data
- Some metadata is missing from the transactions and blocks (e.g. version numbers)
- Addresses and wallets have been merged into a single class which handles transactions generation and tracks the value of an address. This class subclasses
the simplified payment verification class for simplicity.

Over time, I plan to bring this implementation further in line with Bitcoin, maintaining only those deviations which aren't fundamental and which
signficantly reduce the complexity of the code.

## Plan
This is my plan for the respository:
1. Bring the code further in line with the Bitcoin protocol.
2. Finish implementing TCP communication and wrap everything in Docker containers to allow for more decentralized operation.
3. Move the code to an Org Babel document and write explanations of the major components. There is a lack of relatively detailed explanations of
Bitcoin which include extensive code: I have only been able to find broad descriptions without much reference to specific data structures or
code without significant description, and it is my hope that this repository can fill this gap and prove valuable to other people looking to
learn more about the details of Bitcoin.
