### Design Approach
The design approach for the block construction program was to create a modular and scalable solution. The key concept was to create a valid block by ensuring that each block has a unique identifier and that it is connected to the previous block through a hash function.

### Implementation Details
Pseudo code of the implementation is as follows:

Define a class Block with properties: index, timestamp, data, previous_hash, hash.
The hash is calculated using SHA256 encryption of the block's index, timestamp, data, and the previous block's hash.
Define a class Blockchain with properties: chain.
The chain is an array of Block objects.
In the Blockchain class, define a method add_block(data) to add a new block to the chain. This method creates a new Block with the provided data and the hash of the last block in the chain.

### Results and Performance
The solution works as expected and is able to create a valid blockchain with multiple blocks. The efficiency of the solution is O(1) for adding a new block as it only involves creating a new block and appending it to the chain.

### Conclusion
Solving this problem provided a deeper understanding of how blockchains work. Potential areas for future improvement include adding validation to ensure the integrity of the blockchain and implementing a proof-of-work system. Resources consulted include various online articles and tutorials on blockchain technology.