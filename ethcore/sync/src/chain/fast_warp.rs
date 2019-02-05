// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.
use std::collections::{HashSet, HashMap};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::str::FromStr;

// use ethcore_blockchain::{BlockChainDB};
use block_sync::{BlockDownloader};
use bytes::Bytes;
use db_utils::open_db_default;
use ethcore::account_db::{AccountDBMut};
use ethereum_types::{H256, U256};
use ethtrie::{TrieDBMut, RlpCodec};
use hash::{KECCAK_EMPTY, KECCAK_NULL_RLP};
use hashdb::HashDB;
use journaldb::{self, JournalDB, Algorithm};
use rlp::{Rlp, Prototype};
use trie::{TrieMut, NibbleSlice, NodeCodec, node::Node};
use types::basic_account::BasicAccount;

#[derive(Clone, Debug)]
pub enum NodeDataRequest {
	/// The request is for a path in the state tree
	State,
	/// The request is for a storage path in the account's
	/// storage trie (the H256 value is the account's hash)
	Storage(H256),
	/// The request is for an account's code
	/// (the H256 value is the account's hash)
	Code(H256),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
/// State of the Fast-Warp sync
pub struct FastWarpState {
	/// Sync is waiting for something (more peers, queue was full, etc.)
	Idle,
	/// Syncing the block headers from peers
	BlockSync(BlockDownloader),
	/// Syncing the state with FastWarp requests
	StateSync,
	/// Filling the state with NodeData requests
	StateFill,
}

pub struct FastWarp {
	next_account_from: H256,
	next_storage_from: H256,

	// (last account hash ; last account storage root)
	last_account: (H256, H256),
	// Current state root
	state_root: H256,
	finished: bool,
	finished_trie: bool,

	// Target for the Fast-Warp sync
	pub fw_target: H256,
	// Target for post-FW sync, via. GetNodeData
	pub sync_target: H256,
	// Node Data keys to query to remote peer
	pub node_data_queries: HashSet<H256>,
	// Nibble Prefixes for each key
	pub node_data_prefixes: HashMap<H256, Vec<u8>>,
	// What requests have been sent
	pub node_data_requests: HashMap<H256, NodeDataRequest>,

	db: Box<JournalDB>,
}

impl FastWarp {
	pub fn new() -> std::io::Result<FastWarp> {
		let db = open_db_default(&FastWarp::db_path())?;
		let kvdb = db.key_value().clone();
		println!("Trying to create JournalDB...");
		let db = journaldb::new(kvdb, Algorithm::OverlayRecent, ::ethcore_db::COL_STATE);

		Ok(FastWarp {
			next_account_from: H256::zero(),
			next_storage_from: H256::zero(),

			last_account: (H256::zero(), H256::zero()),
			state_root: KECCAK_NULL_RLP,
			finished: false,
			finished_trie: false,

			node_data_queries: HashSet::new(),
			node_data_prefixes: HashMap::new(),
			node_data_requests: HashMap::new(),

			// State root hash of block ??? (on Kovan)
			fw_target: H256::from_str(
				&::std::env::var("TARGET").unwrap_or(
					"8f6f82f44f4f2a5b18ba5612a663484e78c779aec1c979d5a41848def2d105b6".to_string()
				)
			).unwrap(),
			// State root hash of block 0x1bb00 (on Kovan)
			sync_target: H256::from("fffffcbca8d0fe343fddf11392f17e4f9b506746afe2dab62f772389194f8a7e"),

			db,
		})
	}

	fn db_path() -> PathBuf {
		PathBuf::from("/tmp/fast-warp")
	}

	pub fn finished(&self) -> bool {
		return self.finished
	}

	pub fn finished_trie(&self) -> bool {
		return self.finished_trie
	}

	fn finish(&mut self) {
		self.finished = true;
		let success = self.state_root == self.fw_target;
		if success {
			info!("Successful fast-warp!");
			// First, query the head of the state tree
			self.node_data_requests.insert(self.sync_target, NodeDataRequest::State);
			self.node_data_queries = HashSet::from_iter(vec![ self.sync_target ]);
		} else {
			warn!("Unsuccessful fast-warp: target={:?} vs. current={:?}", self.fw_target, self.state_root);
		}

		// let account_trie = TrieDB::new(self.db.as_hashdb_mut(), &self.state_root);
		// println!("Trie: {:?}", account_trie);
	}

	pub fn process_node_data(&mut self, node_data_hashes: Vec<H256>, r: &Rlp) {
		if node_data_hashes.len() != r.item_count().unwrap_or(0) {
			debug!(target: "sync",
				"Invalid NodeData RLP: asked for {} hashes, got {} items",
				node_data_hashes.len(),
				r.item_count().unwrap_or(0),
			);
		}

		let mut accounts_to_insert = Vec::new();

		for (rlp_data, node_data_key) in r.iter().zip(node_data_hashes) {
			let request = self.node_data_requests.remove(&node_data_key).unwrap();
			let state_data: Bytes = rlp_data.data().expect("Invalid RLP").to_vec();

			match request {
				NodeDataRequest::Code(account_hash) => {
					warn!("Got code request: acc={:?} data={:?}", account_hash, state_data);
					continue;
				},
				_ => (),
			}

			let node = RlpCodec::decode(&state_data).expect("Invalid RlpCodec");

			let prefix = self.node_data_prefixes.remove(&node_data_key).unwrap_or_default();
			// The request that was sent should always exist!
			self.node_data_queries.remove(&node_data_key);

			match node {
				Node::Empty => (),
				Node::Leaf(path, data) => {

					let prefix_len = prefix.len();
					let mut nibble_builder = Vec::new();
					let mut i = 0;
					let mut offset = 0;
					if prefix_len % 2 == 1 {
						nibble_builder.push(prefix[0]);
						i = 1;
						offset = 1;
					}
					while i < prefix_len {
						nibble_builder.push(16 * prefix[i] + prefix[i + 1]);
						i += 2;
					}

					let nibble_prefix = NibbleSlice::new_offset(&nibble_builder, offset);
					let hash_nible = NibbleSlice::new_composed(&nibble_prefix, &path);

					let key_vec = hash_nible.encoded(false);
					// First byte is 0 if length is even ; it should always be 32
					let key = H256::from_slice(&key_vec[1..]);
					warn!("Got NodeLeaf: r={:?} ; k={:?} ; data={:?}", request, key, data);

					match request {
						NodeDataRequest::State => {
							let account_hash = key;
							let account_trie = if self.state_root != KECCAK_NULL_RLP {
								TrieDBMut::from_existing(self.db.as_hashdb_mut(), &mut self.state_root).unwrap()
							} else {
								TrieDBMut::new(self.db.as_hashdb_mut(), &mut self.state_root)
							};

							let account: BasicAccount = Rlp::new(data).as_val().expect("Invalid Account data");

							if let Some(account_in_db) = account_trie.get(&account_hash).unwrap() {
								let account_in_db: BasicAccount = Rlp::new(&account_in_db)
									.as_val().expect("Invalid Account data in DB");

								if account_in_db != account {
									accounts_to_insert.push((account_hash, account));
								}
							} else {
								accounts_to_insert.push((account_hash, account));
							}
						},
						_ => {
							warn!("Got request...");
						},
					}
				},
				Node::Extension(path, key_bytes) => {
					let key_rlp = Rlp::new(key_bytes);
					let key: H256 = match key_rlp.prototype().expect("Invalid Extension Key RLP") {
						Prototype::Null => continue,
						Prototype::Data(0) => continue,
						Prototype::Data(32) => {
							key_rlp.as_val().expect("Invalid Extension Key RLP")
						},
						proto => {
							println!("Invalid Extension Key RLP: {:?}", proto);
							continue;
						},
					};

					if !self.db.as_hashdb().contains(&key) {
						let mut ext_prefixes = prefix.clone();
						let mut path_nibbles: Vec<u8> = path.iter().collect();
						ext_prefixes.append(&mut path_nibbles);

						self.node_data_prefixes.insert(key, ext_prefixes);
						self.node_data_requests.insert(key, request.clone());
						self.node_data_queries.insert(key);
					}
				},
				Node::Branch(branches, data_opt) => {
					for (branch_idx, branch_rlp) in branches.iter().enumerate() {
						let branch_rlp = Rlp::new(branch_rlp);
						let branch_key: H256 = match branch_rlp.prototype()
								.expect("Invalid Branch RLP")
						{
							Prototype::Null => continue,
							Prototype::Data(0) => continue,
							Prototype::Data(32) => {
								branch_rlp.as_val().expect("Invalid Branch RLP")
							},
							proto => {
								println!("Invalid branch RLP: {:?}", proto);
								continue;
							},
						};

						if !self.db.as_hashdb().contains(&branch_key) {
							// trace!(target: "sync", "Doesn't have branch in DB {:#?}", branch_key);
							let mut branch_prefixes = prefix.clone();
							branch_prefixes.push(branch_idx as u8);
							self.node_data_prefixes.insert(branch_key, branch_prefixes);
							self.node_data_requests.insert(branch_key, request.clone());
							self.node_data_queries.insert(branch_key);
						}
					}
					if let Some(branch_data) = data_opt {
						warn!("Node Branch Data: r={:?} ; d={:#?}", request, branch_data);
					}
				},
			}
		}

		if accounts_to_insert.len() > 0 {
			// trace!(target: "sync", "New/Modified accounts detected!\n{:#?}", accounts_to_insert);

			let mut storage_root_queries = HashSet::new();
			let mut code_hash_queries = HashSet::new();

			{
				let db = self.db.as_hashdb_mut();
				for (account_hash, account) in accounts_to_insert.iter() {
					let acct_db = AccountDBMut::from_hash(db, *account_hash);

					if account.storage_root != KECCAK_NULL_RLP &&!acct_db.contains(&account.storage_root) {
						storage_root_queries.insert(account.storage_root);

						self.node_data_requests.insert(account.storage_root, NodeDataRequest::Storage(account_hash.clone()));
						self.node_data_queries.insert(account.storage_root);
					}
					if account.code_hash != KECCAK_EMPTY && !acct_db.contains(&account.code_hash) {
						code_hash_queries.insert(account.code_hash);

						self.node_data_requests.insert(account.code_hash, NodeDataRequest::Code(account_hash.clone()));
						self.node_data_queries.insert(account.code_hash);
					}
				}
			}

			if storage_root_queries.len() > 0 {
				trace!(target: "sync", "Storage root queries: {:?}", storage_root_queries);
			}
			if code_hash_queries.len() > 0 {
				trace!(target: "sync", "Code hash queries: {:?}", code_hash_queries);
			}

			{
				let mut account_trie = if self.state_root != KECCAK_NULL_RLP {
					TrieDBMut::from_existing(self.db.as_hashdb_mut(), &mut self.state_root).unwrap()
				} else {
					TrieDBMut::new(self.db.as_hashdb_mut(), &mut self.state_root)
				};

				for (hash, account) in accounts_to_insert.iter() {
					let thin_rlp = ::rlp::encode(account);
					account_trie.insert(&hash, &thin_rlp).unwrap();
				}
			}

			self.db.flush();
			trace!(target: "sync", "New state root: {:#?}", self.state_root);
		}

		if self.node_data_queries.len() == 0 {
			info!(target: "sync", "Finished Node Data requests");
			self.finished_trie = true;
		}
	}

	pub fn process_chunk(&mut self, r: &Rlp) {
		// This should be [account_hash, storage_key, storage_root]
		let num_accounts = r.item_count().unwrap();

		if num_accounts == 0 {
			self.finish();
			return;
		}

		let mut last_item = (H256::zero(), H256::zero(), H256::zero());
		let mut account_pairs = Vec::with_capacity(num_accounts);
		account_pairs.resize(num_accounts, (H256::new(), Vec::new()));

		let mut should_finish = false;

		{
			let db = self.db.as_hashdb_mut();

			for (idx, (account_rlp, account_pair)) in r.into_iter().zip(account_pairs.iter_mut()).enumerate() {
				let account_hash: H256 = account_rlp.val_at(0).expect("Invalid account_hash");

				// trace!(target: "sync", "Going through account {:?}", account_hash);

				let mut acct_db = AccountDBMut::from_hash(db, account_hash);
				let mut storage_root = if self.last_account.0 == account_hash {
					self.last_account.1
				}  else {
					H256::zero()
				};
				let mut last_storage_key = H256::zero();

				let storage_rlp = account_rlp.at(2).expect("Invalid storage_rlp");
				let storage_count = storage_rlp.item_count().expect("Invalid storage_count");

				{
					let mut storage_trie = if storage_root.is_zero() {
						TrieDBMut::new(&mut acct_db, &mut storage_root)
					} else {
						TrieDBMut::from_existing(&mut acct_db, &mut storage_root)
							.expect("Couldn't open TrieDB from storage_root")
					};

					for pair_rlp in storage_rlp.iter() {
						let k: Bytes  = pair_rlp.val_at(0).expect("Invalid storage_key RLP");
						let v: Bytes = pair_rlp.val_at(1).expect("Invalid storage_value RLP");

						last_storage_key = H256::from_slice(&k);
						storage_trie.insert(&k, &v).expect("Failed to insert KV pair in storage Trie");
					}
				}

				if storage_count == 0 {
					// trace!(target: "sync", "No storage!");
					// If there is no storage and only one element, which is the same as previously,
					// it is OVER
					if num_accounts == 1 && account_hash == self.last_account.0 {
						should_finish = true;
						break;
					}
				}

				let account_data_rlp = account_rlp.at(1).expect("Invalid account_data RLP");
				let account_nonce: U256 = account_data_rlp.val_at(0).expect("Invalid account nonce RLP");
				let account_balance: U256 = account_data_rlp.val_at(1).expect("Invalid account nonce RLP");
				let account_storage_root: H256 = account_data_rlp.val_at(2).expect("Invalid account nonce RLP");

				let code_hash = match account_data_rlp.item_count().expect("Invalid account_data RLP") {
					3 => KECCAK_EMPTY,
					4 => {
						let code: Bytes = account_data_rlp.val_at(3).expect("Invalid code");
						let code_hash = acct_db.insert(&code);

						code_hash
					},
					i => panic!("Invalid account_data_rlp items: {}", i),
				};

				let acc = BasicAccount {
					nonce: account_nonce,
					balance: account_balance,
					storage_root: storage_root,
					code_hash: code_hash,
				};

				let thin_rlp = ::rlp::encode(&acc);
				*account_pair = (account_hash, thin_rlp);

				// Ie. not the last one, storage_root should be known
				let is_last_item = idx == num_accounts - 1;
				if !is_last_item {
					if account_storage_root != storage_root {
						trace!(target: "sync",
							"Invalid storage_root! expected {:?}, got {:?}",
							account_storage_root, storage_root
						);
					}
				} else {
					last_item = (account_hash, last_storage_key, storage_root);
				}
			}
		}

		if should_finish {
			self.db.flush();
			self.finish();
			return;
		}

		let progress = ((last_item.0[0] as u32 * 256 + last_item.0[1] as u32) * 100)  as f64 / (256 * 256) as f64;

		println!(
			"Got fast-warp data up to {:?}::{:?} ({} accounts) progress={}%",
			last_item.0, last_item.1, num_accounts,
			progress,
		);

		{
			let mut account_trie = if self.state_root != KECCAK_NULL_RLP {
				TrieDBMut::from_existing(self.db.as_hashdb_mut(), &mut self.state_root).unwrap()
			} else {
				TrieDBMut::new(self.db.as_hashdb_mut(), &mut self.state_root)
			};

			for (hash, thin_rlp) in account_pairs {
				account_trie.insert(&hash, &thin_rlp).unwrap();
			}
		}

		println!("Current state root: {:?}", self.state_root);
		self.db.flush();
		self.update(last_item.0, last_item.1, last_item.2);
	}

	pub fn update(&mut self, account_from: H256, storage_from: H256, storage_root: H256) {
		self.next_account_from = account_from;
		self.next_storage_from = H256::from(U256::from(storage_from) + U256::one());

		self.last_account = (account_from, storage_root);
	}

	pub fn get_request(&self) -> (H256, H256) {
		(self.next_account_from, self.next_storage_from)
	}
}
