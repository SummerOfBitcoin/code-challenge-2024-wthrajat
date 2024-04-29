use core::panic;
use libsecp256k1::{verify, Message, PublicKey, Signature};
use log;
use ripemd::Ripemd160;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::convert::TryInto;
use std::error::Error;
use std::fs;
use std::fs::write;
use std::time::{SystemTime, UNIX_EPOCH};

use num_bigint::BigUint;


/// Structs for deserializing the JSON files and necessary helper functions

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct Input {
    txid: String,
    vout: u32,
    prevout: PrevOut,
    scriptsig: String,
    scriptsig_asm: String,
    witness: Option<Vec<String>>,
    is_coinbase: bool,
    sequence: u32,
    inner_witnessscript_asm: Option<String>,
    inner_redeemscript_asm: Option<String>,
}


#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct PrevOut {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: Option<String>,
    value: u64,
}

#[derive(Eq, PartialEq, Hash, Clone)]
struct TxNode {
    txid: String,
    fee: u64,
    weight: u64,
    tx: Transaction,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct Transaction {
    version: u32,
    locktime: u32,
    vin: Vec<Input>,
    vout: Vec<Output>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
struct Output {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: Option<String>,
    value: u64,
}



/// Implement traits for TxNode to use it in BinaryHeap
/// We will use the fee/weight ratio to compare the TxNodes
impl Ord for TxNode {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_ratio = self.fee as f64 / self.weight as f64;
        let other_ratio = other.fee as f64 / other.weight as f64;
        self_ratio
            .partial_cmp(&other_ratio)
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for TxNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn mine_bro() {
    let block_height: u32 = 55; // this happens to be my roll number :)
    let mut valid_tx_vector: Vec<Transaction> = Vec::new();
    let mut valid_wtxid: Vec<Vec<u8>> = Vec::new();
    let mut tx_to_tx_node: HashMap<Transaction, TxNode> = HashMap::new();

    let coinbase_in = "0000000000000000000000000000000000000000000000000000000000000000";
    let decoded_coinbase = hex::decode(coinbase_in).unwrap();
    valid_wtxid.push(decoded_coinbase);

    for entry in fs::read_dir("../mempool").unwrap() {
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();

        let (second_check, fee) = ip_op_check(tx.clone());

        let third_check: bool = check_sig(tx.clone());

        let fourth_check: bool = locktime_check(tx.clone(), block_height);

        let weight: u64 = weight_test(tx.clone());

        if second_check && third_check && fourth_check {
            let txid_str = txids_collect(tx.clone());
            let tx_node = TxNode {
                txid: txid_str.clone(),
                fee,
                weight,
                tx: tx.clone(),
            };
            if txid_str == "e942daaa7f3776f1d640ade0106b181faa9a794708ab76b2e99604f26e4ed807" {
                continue;
            }
            tx_to_tx_node.insert(tx.clone(), tx_node);
            valid_tx_vector.push(tx.clone());
        }
    }

    let mut all_ins: HashSet<String> = HashSet::new();
    let mut all_outs: HashSet<String> = HashSet::new();
    let mut scriptpubkey_to_tx: HashMap<String, Transaction> = HashMap::new();

    for tx in valid_tx_vector.clone() {
        let tx_clone = tx.clone();

        for ins in tx.vin {
            all_ins.insert(ins.prevout.scriptpubkey.clone());
        }

        for outs in tx.vout {
            all_outs.insert(outs.scriptpubkey.clone());
            scriptpubkey_to_tx.insert(outs.scriptpubkey.clone(), tx_clone.clone());
        }
    }

    let mut graph: HashMap<TxNode, Vec<TxNode>> = HashMap::new();

    for tx in valid_tx_vector {
        let tx_clone = tx.clone();
        let curr_tx_node = tx_to_tx_node.get(&tx_clone).unwrap();

        for ins in tx.vin {
            if all_outs.contains(&ins.prevout.scriptpubkey.clone()) {
                let parent_tx = scriptpubkey_to_tx.get(&ins.prevout.scriptpubkey).unwrap();
                let parent_tx_node = tx_to_tx_node.get(parent_tx).unwrap().clone();
                graph
                    .entry(parent_tx_node)
                    .or_insert_with(Vec::new)
                    .push(curr_tx_node.clone());
            }
        }
        graph.entry(curr_tx_node.clone()).or_insert_with(Vec::new);
    }

    let mut heap = BinaryHeap::new();

    for (node, children) in graph.iter() {
        if children.is_empty() {
            heap.push(node.clone());
        }
    }

    let weight_maximum: u64 = 4_000_000;
    let mut block_weight: u64 = 0;
    let mut fees: u64 = 0;
    let mut accepted_txs: Vec<String> = Vec::new();
    let mut wtxid_strings = Vec::new();
    let mut i = 0;
    while let Some(node) = heap.pop() {
        if block_weight + node.weight <= weight_maximum {
            block_weight += node.weight;
            fees += node.fee;
            accepted_txs.push(node.txid.clone());
            if i != 0 {
                let wtxid = wtxid_get(node.tx.clone());
                wtxid_strings.push(node.txid.clone() + " " + &hex::encode(wtxid.clone()));
                valid_wtxid.push(wtxid.clone());
            }

            if let Some(children) = graph.get(&node).cloned() {
                for child in children {
                    let incomings = graph.get_mut(&child).unwrap();
                    incomings.remove(0);
                    if incomings.is_empty() {
                        heap.push(tx_to_tx_node.get(&child.tx.clone()).unwrap().clone());
                    }
                }
            }
        }
        i += 1;
    }
    let merkle_root = merkle_root_get(accepted_txs.clone());

    let block_header = block_header_get(merkle_root);

    let merkle_root_wtxid = merkle_root_wtxid_get(&valid_wtxid.clone());
    let coinbase_transaction = coinbase_tx_get(
        block_height,
        fees,
        5_000_000_000,
        merkle_root_wtxid.clone().to_vec(),
    );

    let mut blockdata: Vec<String> = Vec::new();
    blockdata.push(block_header);
    blockdata.push(coinbase_transaction);
    blockdata.extend(accepted_txs);

    write_to_output_file(blockdata, "../output.txt").unwrap();
}


fn locktime_check(tx: Transaction, block_height: u32) -> bool {
    if tx.vin.iter().all(|input| input.sequence == 0xFFFFFFFF) {
        return true;
    }

    if tx.locktime < 500_000_000 {
        if tx.locktime > block_height {
            return false;
        }
    } else {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("back time")
            .as_secs() as u32;
        if tx.locktime > current_time {
            return false;
        }
    }
    true
}

fn write_to_output_file(block: Vec<String>, filename: &str) -> Result<(), Box<dyn Error>> {
    let contents = block.join("\n");
    write(filename, contents)?;
    Ok(())
}

fn weight_calc_right(non_witness: Vec<u8>, witness_and_markerflag: Vec<u8>) -> u64 {
    (non_witness.len() as u64) * 4 + (witness_and_markerflag.len() as u64)
}

fn block_header_get(merkle_root: [u8; 32]) -> String {
    let mut nonce: u32 = 0;
    let mut block_header: String = "".to_string();

    let target = "0000ffff00000000000000000000000000000000000000000000000000000000";
    let target = hex::decode(target).unwrap();
    let target = BigUint::from_bytes_be(&target);

    loop {
        let mut predigest: Vec<u8> = Vec::new();

        let version: u32 = 0x00000004;
        predigest.extend_from_slice(&version.to_le_bytes());

        let prev_block_hash = vec![0u8; 32];
        predigest.extend_from_slice(&prev_block_hash);

        predigest.extend_from_slice(&merkle_root);

        let now = SystemTime::now();
        let since_the_epoch = now
            .duration_since(UNIX_EPOCH)
            .expect("reverse time!!!! bro!!!!");
        let time = since_the_epoch.as_secs() as u32;
        predigest.extend_from_slice(&time.to_le_bytes());

        let bits: u32 = 0xffff001f;
        predigest.extend_from_slice(&bits.to_be_bytes());

        predigest.extend_from_slice(&nonce.to_le_bytes());

        let mut header_candidate = sha256_hash(&sha256_hash(&predigest));
        header_candidate.reverse();
        let header_for_calc = BigUint::from_bytes_be(&header_candidate);
        if header_for_calc < target {
            block_header = hex::encode(predigest);
            break;
        }

        nonce += 1;
    }

    block_header
}



fn coinbase_tx_get(
    block_height: u32,
    fees: u64,
    block_reward: u64,
    witness_root_hash: Vec<u8>,
) -> String {
    let mut tx: Vec<u8> = Vec::new();

    let version: u32 = 0x00000002;
    tx.extend_from_slice(&version.to_le_bytes());

    let marker: u8 = 0x00;
    tx.push(marker);
    let flag: u8 = 0x01;
    tx.push(flag);

    let input: u8 = 0x01;
    tx.push(input);

    let coinbase_input = "0000000000000000000000000000000000000000000000000000000000000000";
    let coinbase_input = hex::decode(coinbase_input).unwrap();
    tx.extend_from_slice(&coinbase_input);

    let output_value: u32 = 0xffffffff;
    tx.extend_from_slice(&output_value.to_le_bytes());

    let mut coinbase: Vec<u8> = Vec::new();
    let mut temp_first: Vec<u8> = Vec::new();

    let height = block_height.to_le_bytes();
    let height_size = height.len() as u8;
    temp_first.push(height_size);
    temp_first.extend_from_slice(&height);

    coinbase.extend_from_slice(&temp_first);

    let mut temp_second: Vec<u8> = Vec::new();
    let random_data: u32 = 0x69966996;
    temp_second.extend_from_slice(&random_data.to_le_bytes());
    coinbase.push(temp_second.len() as u8);

    coinbase.extend_from_slice(&temp_second);

    let coinbase_len = coinbase.len() as u64;
    let coinbase_varint = varint_convert_bro(coinbase_len);
    tx.extend_from_slice(&coinbase_varint[..]);
    tx.extend_from_slice(&coinbase);

    let sequence: u32 = 0xffffffff;
    tx.extend_from_slice(&sequence.to_le_bytes());

    let output: u8 = 0x02;
    tx.push(output);

    let output_value: u64 = fees + block_reward;
    tx.extend_from_slice(&output_value.to_le_bytes());

    let script_str = "6a026996";
    let script = hex::decode(script_str).unwrap();
    tx.push(script.len() as u8);
    tx.extend_from_slice(&script);

    let output_value: u64 = 0x0000000000000000;
    tx.extend_from_slice(&output_value.to_le_bytes());

    let mut commit: Vec<u8> = Vec::new();
    let commit_data = "6a24aa21a9ed";
    let commit_data = hex::decode(commit_data).unwrap();
    commit.extend_from_slice(&commit_data);

    let mut script: Vec<u8> = Vec::new();
    script.extend_from_slice(&witness_root_hash);

    let witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000";
    let witness_reserved_value = hex::decode(witness_reserved_value).unwrap();
    script.extend_from_slice(&witness_reserved_value[..]);
    let hash = sha256_hash(&sha256_hash(&script));
    commit.extend_from_slice(&hash);
    tx.push(commit.len() as u8);
    tx.extend_from_slice(&commit);

    let witness: u8 = 0x01;
    tx.push(witness);

    let witness_size: u8 = 0x20;
    tx.push(witness_size);

    let witness_data = "0000000000000000000000000000000000000000000000000000000000000000";
    let witness_data = hex::decode(witness_data).unwrap();
    tx.extend_from_slice(&witness_data);

    let locktime: u32 = 0x00000000;
    tx.extend_from_slice(&locktime.to_le_bytes());

    hex::encode(tx)

}

fn merkle_root_get(mut accepted_txns: Vec<String>) -> [u8; 32] {
    let mut merkle_root: Vec<[u8; 32]> = Vec::new();
    let mut temp_array: Vec<[u8; 32]> = Vec::new();

    if accepted_txns.len() % 2 == 1 {
        accepted_txns.push(accepted_txns.last().unwrap().clone());
    }

    for tx in accepted_txns {
        let txid = hex::decode(tx).unwrap();

        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();

        let rev_txid_in_bytes: [u8; 32] = match reversed_txid.try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Vec len 32 honi chahiye thi, but it was {}", txid.len()),
        };

        merkle_root.push(rev_txid_in_bytes.try_into().unwrap());
    }

    while merkle_root.len() > 1 {
        if merkle_root.len() % 2 == 1 {
            merkle_root.push(*merkle_root.last().unwrap());
        }

        temp_array.clear();
        for chunks in merkle_root.chunks(2) {
            let mut combined = Vec::new();
            combined.extend_from_slice(&chunks[0]);
            if let Some(second) = chunks.get(1) {
                combined.extend_from_slice(second);
            }
            let hash = sha256_hash(&sha256_hash(&combined));
            temp_array.push(hash.try_into().unwrap());
        }

        merkle_root = temp_array.clone();
    }

    merkle_root[0]
}

fn ip_op_check(tx: Transaction) -> (bool, u64) {
    let mut inputs: u64 = 0;
    let mut outputs: u64 = 0;

    for ins in tx.vin {
        inputs += ins.prevout.value;
    }

    for outs in tx.vout {
        outputs += outs.value;
    }

    (inputs >= outputs, inputs - outputs)
}

fn check_sig(tx: Transaction) -> bool {

    // Now we will check for sigs for all typa txs

    for (index, ins) in tx.vin.iter().enumerate() {
        match &*ins.prevout.scriptpubkey_type {
            "v1_p2tr" => {
                continue;
            }
            "v0_p2wpkh" => {
                let sign_in_witness = ins.witness.clone().unwrap()[0].clone();
                let sign_to_bytes = hex::decode(sign_in_witness).unwrap();

                let sign_to_verify = &sign_to_bytes[..sign_to_bytes.len() - 1];

                let pubkey = ins.witness.clone().unwrap()[1].clone();
                let pubkey_in_bytes_vec = hex::decode(pubkey).unwrap();
                let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();

                let sighash = sign_to_bytes.last().cloned().unwrap();

                let mut scriptcode: Vec<u8> = Vec::new();
                scriptcode.push(0x19);
                scriptcode.push(0x76);
                scriptcode.push(0xa9);
                scriptcode.push(0x14);
                let pub_hash = hash160(&pubkey_in_bytes_vec);
                scriptcode.extend_from_slice(&pub_hash);
                scriptcode.push(0x88);
                scriptcode.push(0xac);

                let hash = commitment_hash_segwit_get_bro(
                    tx.clone(),
                    tx.version,
                    sighash as u32,
                    tx.locktime,
                    scriptcode,
                    ins.sequence,
                    ins.prevout.value,
                    ins.txid.clone(),
                    ins.vout,
                );

                let signature = Signature::parse_der(sign_to_verify).unwrap();
                let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes).unwrap();
                let msg = Message::parse_slice(&hash).unwrap();

                let ret = verify(&msg, &signature, &pubkey);

                if ret == false {
                    return false;
                }
            }
            "v0_p2wsh" => {
                let witness_len = ins.witness.clone().unwrap().len();

                let mut signatures_vector: Vec<Vec<u8>> = Vec::new();
                let mut sighash_vector: HashMap<Vec<u8>, u32> = HashMap::new();
                let mut pubkey_vec: Vec<[u8; 33]> = Vec::new();
                let mut pubkey_hash_vec: Vec<Vec<u8>> = Vec::new();

                for i in 0..(witness_len - 1) {
                    let witness_to_bytes =
                        hex::decode(ins.witness.clone().unwrap()[i].clone()).unwrap();

                    if witness_to_bytes.is_empty() {
                        continue;
                    }

                    let sign_to_verify = witness_to_bytes[..witness_to_bytes.len() - 1].to_vec();
                    let sighash = witness_to_bytes.last().cloned().unwrap();

                    signatures_vector.push(sign_to_verify.clone());
                    sighash_vector.insert(sign_to_verify, sighash as u32);
                }

                let pubkey_vec_in_string = ins.witness.clone().unwrap()[witness_len - 1].clone();
                let number_sign_req = pubkey_vec_in_string[0..2].to_string();
                let number_sign_req = u32::from_str_radix(&number_sign_req, 16).unwrap();
                if number_sign_req < 0x50 || number_sign_req > 0x60 {
                    return false;
                }
                let number_sign_req = number_sign_req - 0x50;

                if let Some(witness_script_asm) = &ins.inner_witnessscript_asm {
                    let parts: Vec<&str> = witness_script_asm.split("OP_PUSHBYTES_33 ").collect();
                    for i in 1..parts.len() {
                        let pubkey_hex = parts[i].split_whitespace().next().unwrap();
                        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
                        let pubkey_in_bytes: [u8; 33] = pubkey_bytes.try_into().unwrap();
                        pubkey_vec.push(pubkey_in_bytes);
                    }
                }
                for pubkey in pubkey_vec.clone() {
                    let _pubkey_in_string = hex::encode(pubkey);

                    pubkey_hash_vec.push(sha256_hash(&pubkey.clone()));
                }

                let mut total_ok: u32 = 0;

                for sig in signatures_vector {
                    let sign = Signature::parse_der(&sig).unwrap();

                    for (counter, pubkey) in pubkey_vec.iter().enumerate() {
                        let _pubkey_hash = pubkey_hash_vec[counter].clone();

                        let mut scriptcode: Vec<u8> = Vec::new();
                        let redeem_script_str =
                            ins.witness.clone().unwrap()[witness_len - 1].clone();
                        let rs_vec = hex::decode(redeem_script_str).unwrap();
                        let rs_size = rs_vec.len() as u64;
                        let rs_size_in_varint = varint_convert_bro(rs_size);
                        scriptcode.extend_from_slice(&rs_size_in_varint);
                        scriptcode.extend_from_slice(&rs_vec);

                        let hash = commitment_hash_segwit_get_bro(
                            tx.clone(),
                            tx.version,
                            sighash_vector[&sig.clone()],
                            tx.locktime,
                            scriptcode,
                            ins.sequence,
                            ins.prevout.value,
                            ins.txid.clone(),
                            ins.vout,
                        );

                        let pubkey = PublicKey::parse_compressed(&pubkey).unwrap();
                        let msg = Message::parse_slice(&hash).unwrap();

                        let ret = verify(&msg, &sign, &pubkey);
                        if ret {
                            total_ok += 1;
                        }
                    }
                }

                if total_ok < number_sign_req {
                    return false;
                }
            }
            "p2sh" => {
                if ins.witness.is_none() {
                    return false;
                } else if ins.witness.as_ref().unwrap().len() == 2 {
                    let sign_in_witness = ins.witness.clone().unwrap()[0].clone();
                    let sign_to_bytes = hex::decode(sign_in_witness).unwrap();

                    let sign_to_verify = &sign_to_bytes[..sign_to_bytes.len() - 1];

                    let pubkey = ins.witness.clone().unwrap()[1].clone();
                    let pubkey_in_bytes_vec = hex::decode(pubkey).unwrap();
                    let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes_vec.clone().try_into().unwrap();

                    let sighash = sign_to_bytes.last().cloned().unwrap();

                    let mut scriptcode: Vec<u8> = Vec::new();
                    scriptcode.push(0x19);
                    scriptcode.push(0x76);
                    scriptcode.push(0xa9);
                    scriptcode.push(0x14);
                    let pub_hash = hash160(&pubkey_in_bytes_vec);
                    scriptcode.extend_from_slice(&pub_hash);
                    scriptcode.push(0x88);
                    scriptcode.push(0xac);

                    let hash = commitment_hash_segwit_get_bro(
                        tx.clone(),
                        tx.version,
                        sighash as u32,
                        tx.locktime,
                        scriptcode,
                        ins.sequence,
                        ins.prevout.value,
                        ins.txid.clone(),
                        ins.vout,
                    );

                    let signature = Signature::parse_der(sign_to_verify).unwrap();
                    let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes).unwrap();
                    let msg = Message::parse_slice(&hash).unwrap();

                    let ret = verify(&msg, &signature, &pubkey);

                    if ret == false {
                        return false;
                    }
                } else {
                    let witness_len = ins.witness.clone().unwrap().len();

                    let mut signatures_vector: Vec<Vec<u8>> = Vec::new();
                    let mut sighash_vector: HashMap<Vec<u8>, u32> = HashMap::new();
                    let mut pubkey_vec: Vec<[u8; 33]> = Vec::new();
                    let mut pubkey_hash_vec: Vec<Vec<u8>> = Vec::new();

                    for i in 0..(witness_len - 1) {
                        let witness_to_bytes =
                            hex::decode(ins.witness.clone().unwrap()[i].clone()).unwrap();

                        if witness_to_bytes.is_empty() {
                            continue;
                        }

                        let sign_to_verify =
                            witness_to_bytes[..witness_to_bytes.len() - 1].to_vec();
                        let sighash = witness_to_bytes.last().cloned().unwrap();

                        signatures_vector.push(sign_to_verify.clone());
                        sighash_vector.insert(sign_to_verify, sighash as u32);
                    }

                    let pubkey_vec_in_string =
                        ins.witness.clone().unwrap()[witness_len - 1].clone();

                    let number_sign_req = pubkey_vec_in_string[0..2].to_string();
                    let number_sign_req = u32::from_str_radix(&number_sign_req, 16).unwrap();
                    if number_sign_req < 0x50 || number_sign_req > 0x60 {
                        return false;
                    }
                    let number_sign_req = number_sign_req - 0x50;

                    if let Some(witness_script_asm) = &ins.inner_witnessscript_asm {
                        let parts: Vec<&str> =
                            witness_script_asm.split("OP_PUSHBYTES_33 ").collect();
                        for i in 1..parts.len() {
                            let pubkey_hex = parts[i].split_whitespace().next().unwrap();
                            let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
                            let pubkey_in_bytes: [u8; 33] = pubkey_bytes.try_into().unwrap();
                            pubkey_vec.push(pubkey_in_bytes);
                        }
                    }

                    for pubkey in pubkey_vec.clone() {
                        let _pubkey_in_string = hex::encode(pubkey);
                        pubkey_hash_vec.push(sha256_hash(&pubkey.clone()));
                    }

                    let mut okay_in_total: u32 = 0;

                    for sig in signatures_vector {
                        let sign = Signature::parse_der(&sig).unwrap();

                        for (counter, pubkey) in pubkey_vec.iter().enumerate() {
                            let _pubkey_hash = pubkey_hash_vec[counter].clone();

                            let mut scriptcode: Vec<u8> = Vec::new();
                            let redeem_script_str =
                                ins.witness.clone().unwrap()[witness_len - 1].clone();
                            let rs_vec = hex::decode(redeem_script_str).unwrap();
                            let rs_size = rs_vec.len() as u64;
                            let rs_size_in_varint = varint_convert_bro(rs_size);
                            scriptcode.extend_from_slice(&rs_size_in_varint);
                            scriptcode.extend_from_slice(&rs_vec);

                            let hash = commitment_hash_segwit_get_bro(
                                tx.clone(),
                                tx.version,
                                sighash_vector[&sig.clone()],
                                tx.locktime,
                                scriptcode,
                                ins.sequence,
                                ins.prevout.value,
                                ins.txid.clone(),
                                ins.vout,
                            );

                            let pubkey = PublicKey::parse_compressed(pubkey).unwrap();
                            let msg = Message::parse_slice(&hash).unwrap();

                            let ret = verify(&msg, &sign, &pubkey);
                            if ret {
                                okay_in_total += 1;
                            }
                        }
                    }

                    if okay_in_total < number_sign_req {
                        return false;
                    }
                }
            }
            "p2pkh" => {
                let sig_len_hex = &ins.scriptsig[..2];
                let sig_len_bytes = hex::decode(sig_len_hex).unwrap();
                let convert_to_dec = u8::from_be_bytes(sig_len_bytes.try_into().unwrap()) as usize;

                let sig_w_sighash = &ins.scriptsig[2..(2 + 2 * convert_to_dec)];
                let sighash = &sig_w_sighash[(2 * convert_to_dec - 2)..];
                let sighash = u8::from_str_radix(sighash, 16).unwrap();
                let sig = &sig_w_sighash[..(2 * convert_to_dec - 2)];

                let pubkey_str = &ins.scriptsig[((2 + 2 * convert_to_dec) + 2)..];
                let mut pubkey_in_bytes: Vec<u8> = hex::decode(pubkey_str).unwrap();
                if pubkey_in_bytes.len() == 65 {
                    pubkey_in_bytes = pubkeys_compression(&pubkey_in_bytes);
                }
                let pubkey_in_bytes: [u8; 33] = pubkey_in_bytes.try_into().expect(&format!(
                    "Failed conversion, [pubkey -> bytes]: {:?}",
                    pubkey_str
                ));
                let pubkey = PublicKey::parse_compressed(&pubkey_in_bytes.clone()).unwrap();

                let sig_in_bytes = hex::decode(sig).unwrap();
                let sign = Signature::parse_der(&sig_in_bytes).unwrap();

                let hash = commitment_hash_legacy_get(
                    tx.clone().version,
                    tx.clone(),
                    index as u32,
                    sighash as u32,
                );

                let msg = Message::parse_slice(&hash).unwrap();

                let ret = verify(&msg, &sign, &pubkey);

                if ret == false {
                    return false;
                }
            }
            _ => {
                continue;
            }
        }
    }

    true
}

pub fn pure_p2sh() {
    let mut count = 0;

    for entry in fs::read_dir("../mempool").unwrap() {
        let entry = entry.unwrap();
        let tx: Transaction =
            serde_json::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap();

        for ins in tx.vin {
            if ins.prevout.scriptpubkey_type == "p2sh" && ins.witness.is_none() {
                count += 1;
                println!(
                    "fulfilled our cnditsns!!!! = {:?}",
                    entry.path().file_name().unwrap()
                );

                break;
            }
        }
    }

    log::info!("p2sh transactions number = {:?}", count);
}



fn get_txid(version: u32, inputs: Vec<Vec<u8>>, outputs: Vec<Vec<u8>>, locktime: u32) -> [u8; 32] {
    let mut tx = Vec::new();

    tx.extend_from_slice(&version.to_le_bytes());

    let inputs_length: u64 = inputs.len() as u64;
    let input_length_in_varint = varint_convert_bro(inputs_length);
    tx.extend_from_slice(&input_length_in_varint);

    for input in inputs {
        tx.extend_from_slice(&input);
    }

    let outputs_length: u64 = outputs.len() as u64;
    let output_length_in_varint = varint_convert_bro(outputs_length);
    tx.extend_from_slice(&output_length_in_varint);

    for output in outputs {
        tx.extend_from_slice(&output);
    }

    tx.extend_from_slice(&locktime.to_le_bytes());
    let _raw_txid_in_string = hex::encode(tx.clone());

    let txid = sha256_hash(&sha256_hash(&tx));

    let tx_array: [u8; 32] = match txid.try_into() {
        Ok(arr) => arr,
        Err(_) => panic!("32 vec len daalo but mila = {}", tx.len()),
    };

    tx_array
}

pub fn txids_collect(tx: Transaction) -> String {
    let mut input_vecs: Vec<Vec<u8>> = Vec::new();
    let mut output_vecs: Vec<Vec<u8>> = Vec::new();

    for ins in tx.vin {
        let mut input: Vec<u8> = Vec::new();

        let txid = hex::decode(ins.txid).unwrap();
        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
        input.extend_from_slice(&reversed_txid);
        input.extend_from_slice(&ins.vout.to_le_bytes());

        let scriptSig = hex::decode(ins.scriptsig).unwrap();
        let scriptSig_size = scriptSig.len() as u64;
        let scriptsig_size_in_varint = varint_convert_bro(scriptSig_size);
        input.extend_from_slice(&scriptsig_size_in_varint);
        input.extend_from_slice(&scriptSig);

        input.extend_from_slice(&ins.sequence.to_le_bytes());

        input_vecs.push(input);
    }

    for outs in tx.vout {
        let mut output: Vec<u8> = Vec::new();

        let value = outs.value.to_le_bytes();
        output.extend_from_slice(&value);

        let scriptPubKey = hex::decode(outs.scriptpubkey).unwrap();
        let scriptPubKey_size = scriptPubKey.len() as u64;
        let scriptPubKey_size_in_varint = varint_convert_bro(scriptPubKey_size);
        output.extend_from_slice(&scriptPubKey_size_in_varint);
        output.extend_from_slice(&scriptPubKey);

        output_vecs.push(output);
    }

    let txid = get_txid(tx.version, input_vecs, output_vecs, tx.locktime);
    let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
    hex::encode(reversed_txid)
}

pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut sha256 = Sha256::new();
    sha256.update(input);
    sha256.finalize().to_vec()
}

pub fn hash160(input: &[u8]) -> Vec<u8> {
    let hash = sha256_hash(input);
    let mut ripemd160_hasher = Ripemd160::new();
    ripemd160_hasher.update(hash);
    ripemd160_hasher.finalize().to_vec()
}

fn varint_convert_bro(num: u64) -> Vec<u8> {
    let mut varint = Vec::new();
    if num < 0xfd {
        varint.push(num as u8);
    } else if num <= 0xffff {
        varint.push(0xfd);
        varint.extend_from_slice(&(num as u16).to_le_bytes());
    } else if num <= 0xffffffff {
        varint.push(0xfe);
        varint.extend_from_slice(&(num as u32).to_le_bytes());
    } else {
        varint.push(0xff);
        varint.extend_from_slice(&num.to_le_bytes());
    }
    varint
}

fn commitment_hash_segwit_get_bro(
    tx: Transaction,
    version: u32,
    sighash_type: u32,
    locktime: u32,
    scriptcode: Vec<u8>,
    sequence: u32,
    spent: u64,
    outpoint_txid: String,
    outpoint_vout: u32,
) -> Vec<u8> {
    let mut commitment = Vec::new();

    commitment.extend_from_slice(&version.to_le_bytes());

    let mut temp: Vec<u8> = Vec::new();

    for ins in &tx.vin {
        let txid_in_bytes = hex::decode(ins.txid.clone()).unwrap();
        let mut txid_reversed = txid_in_bytes;
        txid_reversed.reverse();
        temp.extend_from_slice(&txid_reversed);

        temp.extend_from_slice(&ins.vout.to_le_bytes());
    }

    let hashprevouts = sha256_hash(&sha256_hash(&temp));
    commitment.extend_from_slice(&hashprevouts);

    let mut temp2: Vec<u8> = Vec::new();

    for ins in &tx.vin {
        temp2.extend_from_slice(&ins.sequence.to_le_bytes());
    }

    let hashsequence = sha256_hash(&sha256_hash(&temp2));
    commitment.extend_from_slice(&hashsequence);

    let out_txid = hex::decode(outpoint_txid).unwrap();
    let reversed_out_txid: Vec<u8> = out_txid.iter().rev().cloned().collect();
    commitment.extend_from_slice(&reversed_out_txid);
    commitment.extend_from_slice(&outpoint_vout.to_le_bytes());

    commitment.extend_from_slice(&scriptcode);

    commitment.extend_from_slice(&spent.to_le_bytes());

    commitment.extend_from_slice(&sequence.to_le_bytes());

    let mut temp3: Vec<u8> = Vec::new();

    for outs in tx.vout {
        temp3.extend_from_slice(&outs.value.to_le_bytes());

        let scriptpubkey = hex::decode(&outs.scriptpubkey).unwrap();
        let len_in_varint = varint_convert_bro(scriptpubkey.len() as u64);
        temp3.extend_from_slice(&len_in_varint);
        temp3.extend_from_slice(&scriptpubkey);
    }

    let _temp3_string = hex::encode(temp3.clone());

    let temp3_hash = sha256_hash(&sha256_hash(&temp3));
    commitment.extend_from_slice(&temp3_hash);

    commitment.extend_from_slice(&locktime.to_le_bytes());

    commitment.extend_from_slice(&sighash_type.to_le_bytes());

    sha256_hash(&sha256_hash(&commitment))
}

fn commitment_hash_legacy_get(
    version: u32,
    tx: Transaction,
    index: u32,
    sighash_type: u32,
) -> Vec<u8> {
    let mut commitment = Vec::new();

    commitment.extend_from_slice(&version.to_le_bytes());

    let ip_len = tx.vin.clone().len() as u64;
    let ip_len = varint_convert_bro(ip_len);
    commitment.extend_from_slice(&ip_len);

    for (counter, ins) in tx.vin.clone().iter().enumerate() {
        if counter as u32 == index {
            let txid_str = &ins.txid;
            let mut txid_in_bytes = hex::decode(txid_str).unwrap();
            txid_in_bytes.reverse();
            commitment.extend_from_slice(&txid_in_bytes);

            let vout = ins.vout;
            commitment.extend_from_slice(&vout.to_le_bytes());

            let scriptpubkey = hex::decode(&ins.prevout.scriptpubkey).unwrap();
            let scriptpubkey_len = scriptpubkey.len() as u64;
            let scriptpubkey_len = varint_convert_bro(scriptpubkey_len);
            commitment.extend_from_slice(&scriptpubkey_len);
            commitment.extend_from_slice(&scriptpubkey);

            let sequence = ins.sequence;
            commitment.extend_from_slice(&sequence.to_le_bytes());
        } else {
            let txid_str = &ins.txid;
            let mut txid_in_bytes = hex::decode(txid_str).unwrap();
            txid_in_bytes.reverse();
            commitment.extend_from_slice(&txid_in_bytes);

            let vout = ins.vout;
            commitment.extend_from_slice(&vout.to_le_bytes());

            commitment.push(0x00);

            let sequence = ins.sequence;
            commitment.extend_from_slice(&sequence.to_le_bytes());
        }
    }

    let op_len = tx.vout.clone().len() as u64;
    let op_len = varint_convert_bro(op_len);
    commitment.extend_from_slice(&op_len);

    for outs in tx.vout.clone() {
        let value = outs.value;
        commitment.extend_from_slice(&value.to_le_bytes());

        let scriptpubkey = hex::decode(&outs.scriptpubkey).unwrap();
        let scriptpubkey_len = scriptpubkey.len() as u64;
        let scriptpubkey_len = varint_convert_bro(scriptpubkey_len);
        commitment.extend_from_slice(&scriptpubkey_len);
        commitment.extend_from_slice(&scriptpubkey);
    }

    let locktime = tx.locktime;
    commitment.extend_from_slice(&locktime.to_le_bytes());

    commitment.extend_from_slice(&sighash_type.to_le_bytes());

    sha256_hash(&sha256_hash(&commitment))

}

pub fn weight_test(tx: Transaction) -> u64 {
    let mut input_vecs: Vec<Vec<u8>> = Vec::new();
    let mut output_vecs: Vec<Vec<u8>> = Vec::new();
    let mut witness_vecs: Vec<Vec<u8>> = Vec::new();

    for ins in tx.vin.clone() {
        let mut input: Vec<u8> = Vec::new();

        let txid = hex::decode(ins.txid).unwrap();
        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
        input.extend_from_slice(&reversed_txid);
        input.extend_from_slice(&ins.vout.to_le_bytes());

        let scriptSig = hex::decode(ins.scriptsig).unwrap();
        let scriptSig_size = scriptSig.len() as u64;
        let scriptsig_size_in_varint = varint_convert_bro(scriptSig_size);
        input.extend_from_slice(&scriptsig_size_in_varint);
        input.extend_from_slice(&scriptSig);

        input.extend_from_slice(&ins.sequence.to_le_bytes());

        input_vecs.push(input);
    }

    for outs in tx.vout.clone() {
        let mut output: Vec<u8> = Vec::new();

        let value = outs.value.to_le_bytes();
        output.extend_from_slice(&value);

        let scriptPubKey = hex::decode(outs.scriptpubkey).unwrap();
        let scriptPubKey_size = scriptPubKey.len() as u64;
        let scriptPubKey_size_in_varint = varint_convert_bro(scriptPubKey_size);
        output.extend_from_slice(&scriptPubKey_size_in_varint);
        output.extend_from_slice(&scriptPubKey);

        output_vecs.push(output);
    }

    for ins in tx.vin.clone() {
        let mut witness_vec: Vec<u8> = Vec::new();

        if let Some(witness) = ins.witness {
            let witness_len = witness.len() as u64;
            let witness_len_in_varint = varint_convert_bro(witness_len);
            witness_vec.extend_from_slice(&witness_len_in_varint);

            for x in witness {
                let witness_in_bytes = hex::decode(x).unwrap();
                let witness_size = witness_in_bytes.len() as u64;
                let witness_size_in_varint = varint_convert_bro(witness_size);
                witness_vec.extend_from_slice(&witness_size_in_varint);
                witness_vec.extend_from_slice(&witness_in_bytes);
            }
        }

        witness_vecs.push(witness_vec);
    }

    let (witness_data, non_witness_data) =
        dnc_algorithm(tx.clone(), input_vecs, output_vecs, witness_vecs);

    weight_calc_right(non_witness_data, witness_data)
}

fn dnc_algorithm(
    tx: Transaction,
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<u8>>,
) -> (Vec<u8>, Vec<u8>) {
    let mut witness_data: Vec<u8> = Vec::new();
    let mut non_witness_data: Vec<u8> = Vec::new();

    non_witness_data.extend_from_slice(&tx.version.to_le_bytes());

    let flag: u16 = 0x0001;
    witness_data.extend_from_slice(&flag.to_be_bytes());

    let number_of_inputs = inputs.len() as u64;
    let varint_bytes = varint_convert_bro(number_of_inputs);
    non_witness_data.extend_from_slice(&varint_bytes);

    for input in inputs {
        non_witness_data.extend_from_slice(&input);
    }

    let number_of_outputs = outputs.len() as u64;
    let varint_bytes = varint_convert_bro(number_of_outputs);
    non_witness_data.extend_from_slice(&varint_bytes);

    for output in outputs {
        non_witness_data.extend_from_slice(&output);
    }

    for witness in witnesses {
        witness_data.extend_from_slice(&witness);
    }

    non_witness_data.extend_from_slice(&tx.locktime.to_le_bytes());

    (witness_data, non_witness_data)
}

fn txs_assemble_hehe(
    version: u32,
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    witnesses: Vec<Vec<u8>>,
    locktime: u32,
) -> Vec<u8> {
    let mut tx_assembled = Vec::new();

    tx_assembled.extend_from_slice(&version.to_le_bytes());

    let flag: u16 = 0x0001;
    tx_assembled.extend_from_slice(&flag.to_be_bytes());

    let number_of_inputs = inputs.len() as u64;
    let varint_bytes = varint_convert_bro(number_of_inputs);
    tx_assembled.extend_from_slice(&varint_bytes);

    for input in inputs {
        tx_assembled.extend_from_slice(&input);
    }

    let number_of_outputs = outputs.len() as u64;
    let varint_bytes = varint_convert_bro(number_of_outputs);
    tx_assembled.extend_from_slice(&varint_bytes);

    for output in outputs {
        tx_assembled.extend_from_slice(&output);
    }

    for witness in witnesses {
        tx_assembled.extend_from_slice(&witness);
    }

    tx_assembled.extend_from_slice(&locktime.to_le_bytes());

    tx_assembled
}

fn pubkeys_compression(pubkey: &[u8]) -> Vec<u8> {
    let pubkey = PublicKey::parse_slice(pubkey, None).expect("not valid pubkey!!!!!!!!!!!!!!!!!!!");
    let serialized = pubkey.serialize_compressed();
    serialized.to_vec()
}

fn merkle_root_wtxid_get(wtxids: &[Vec<u8>]) -> Vec<u8> {
    let wtxids_str = wtxids
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>();

    merkle_root_get(wtxids_str).to_vec()
}

fn wtxid_get(tx: Transaction) -> Vec<u8> {
    let mut vector_input: Vec<Vec<u8>> = Vec::new();
    let mut vector_output: Vec<Vec<u8>> = Vec::new();
    let mut vector_witness: Vec<Vec<u8>> = Vec::new();

    let mut total: u32 = 0;
    let mut non_segwit: u32 = 0;

    for ins in tx.vin.clone() {
        let mut input: Vec<u8> = Vec::new();

        total += 1;

        if ins.prevout.scriptpubkey_type == "p2pkh" {
            non_segwit += 1;
        }

        let txid = hex::decode(ins.txid).unwrap();
        let reversed_txid: Vec<u8> = txid.iter().rev().cloned().collect();
        input.extend_from_slice(&reversed_txid);
        input.extend_from_slice(&ins.vout.to_le_bytes());

        let scriptSig = hex::decode(ins.scriptsig).unwrap();
        let scriptSig_size = scriptSig.len() as u64;
        let scriptsig_size_in_varint = varint_convert_bro(scriptSig_size);
        input.extend_from_slice(&scriptsig_size_in_varint);
        input.extend_from_slice(&scriptSig);

        input.extend_from_slice(&ins.sequence.to_le_bytes());

        vector_input.push(input);
    }

    for outs in tx.vout.clone() {
        let mut output: Vec<u8> = Vec::new();

        let value = outs.value.to_le_bytes();
        output.extend_from_slice(&value);

        let scriptPubKey = hex::decode(outs.scriptpubkey).unwrap();
        let scriptPubKey_size = scriptPubKey.len() as u64;
        let scriptPubKey_size_in_varint = varint_convert_bro(scriptPubKey_size);
        output.extend_from_slice(&scriptPubKey_size_in_varint);
        output.extend_from_slice(&scriptPubKey);

        vector_output.push(output);
    }

    if total == non_segwit {
        let txid = get_txid(tx.version, vector_input, vector_output, tx.locktime);
        return txid.to_vec().iter().rev().cloned().collect();
    }

    for ins in tx.vin.clone() {
        let mut witness_vec: Vec<u8> = Vec::new();

        if let Some(witness) = ins.witness.clone() {
            let witness_len = witness.len() as u64;
            let witness_len_in_varint = varint_convert_bro(witness_len);
            witness_vec.extend_from_slice(&witness_len_in_varint);

            for x in witness {
                let witness_in_bytes = hex::decode(x).unwrap();
                let witness_size = witness_in_bytes.len() as u64;
                let witness_size_in_varint = varint_convert_bro(witness_size);
                witness_vec.extend_from_slice(&witness_size_in_varint);
                witness_vec.extend_from_slice(&witness_in_bytes);
            }
        } else {
            witness_vec.push(0x00);
        }
        vector_witness.push(witness_vec);
    }

    let serialised = txs_assemble_hehe(
        tx.version,
        vector_input,
        vector_output,
        vector_witness,
        tx.locktime,
    );

    let wtxid = sha256_hash(&sha256_hash(&serialised));

    let reversed_txid = wtxid.iter().rev().cloned().collect();
    reversed_txid
}
