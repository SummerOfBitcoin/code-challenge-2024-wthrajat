### Design Approach

Firstly we serialize the transaction based on the type of input address (specified by `scriptpubkey_type` in the previous output). Then, append the `sighash_type` (found at the end of the signature you are verifying) to the end of the modified transaction byte sequence. Perform a double SHA-256 hash on the trimmed transaction data. Parse the signature, public key, and transaction hash into `SIGNATURE`, `PUBLIC KEY`, and `MESSAGE` objects using the Secp256k1 library. After that, we used ECDSA verification functions to verify the message against the public key and signature.

### Implementation Details
Provide pseudo code of your implementation, including sequence of logic, algorithms and variables used etc.
I took the use of following functions 
```rust
locktime_check(), write_to_output_file(), weight_calc_right(), block_header_get(), coinbase_tx_get(), merkle_root_get(), ip_op_check(), check_sig(), pure_p2sh(), get_txid(), txids_collect(), sha256_hash(), hash160(), varint_convert_bro(), commitment_hash_segwit_get_bro(), commitment_hash_legacy_get(), fees_max_algorithm(), txs_assemble_hehe(), pubkeys_compression(), merkle_root_wtxid_get(), wtxid_get()

```
Description: `locktime_check()` validates transaction locktime; `write_to_output_file()` writes data to an output file; `weight_calc_right()` calculates transaction weight accurately; `block_header_get()` retrieves the block header; `coinbase_tx_get()` retrieves the coinbase transaction; `merkle_root_get()` calculates the Merkle root; `ip_op_check()` validates input and output data; `check_sig()` verifies signatures; `pure_p2sh()` handles pure Pay-to-Script-Hash transactions; `get_txid()` retrieves transaction IDs; `txids_collect()` collects transaction IDs; `sha256_hash()` performs a SHA-256 hash; `hash160()` performs a hash160 operation; `varint_convert_bro()` converts a variable integer; `commitment_hash_segwit_get_bro()` retrieves the SegWit commitment hash; `commitment_hash_legacy_get()` retrieves the legacy commitment hash; `fees_max_algorithm()` calculates maximum transaction fees; `txs_assemble_hehe()` assembles transactions; `pubkeys_compression()` compresses public keys; `merkle_root_wtxid_get()` calculates the Merkle root for a witness transaction ID; and `wtxid_get()` retrieves witness transaction IDs.

### Results and Performance

I scored and the job took around 6 mins 21 seconds on my local machine and around 6 mins on the GitHub actions.
Here is the score:
```
Congratulations! Block is valid with a total fee of 19808182 sats and a total weight of 3995700!
Score: 97
Fee: 19808182
Weight: 3995700
Max Fee: 20616923
Max Weight: 4000000
```

### Conclusion

I have been the part of the January Chaincode cohort where we were given various assignments by the Chaincode guys, so I have some experience in solving those. Sometimes I felt that autograder instructions could have been more detailed but not a big issue!
<br>
Referenes I used are:
- https://learnmeabitcoin.com/
- https://bitcoin.stackexchange.com/
- https://en.bitcoin.it/wiki/Script
- https://wiki.bitcoinsv.io/index.php/Opcodes_used_in_Bitcoin_Script
- https://learn.saylor.org/mod/book/view.php?id=36340&chapterid=18913
- https://bitcoin.stackexchange.com/questions/79266/which-serialization-format-the-transactions-use
- SoB `#assignment` Discord channel