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

//! A provider for the PIP protocol. This is typically a full node, who can
//! give as much data as necessary to its peers.

use std::sync::Arc;

use common_types::blockchain_info::BlockChainInfo;
use common_types::encoded;
use common_types::ids::BlockId;
use common_types::transaction::PendingTransaction;
use ethcore::client::{BlockChainClient, ProvingBlockChainClient, ChainInfo, BlockInfo as ClientBlockInfo};
use ethereum_types::H256;
use parking_lot::RwLock;

use cht::{self, BlockInfo};
use client::{LightChainClient, AsLightClient};
use transaction_queue::TransactionQueue;

use request;

/// Maximum allowed size of a headers request.
pub const MAX_HEADERS_PER_REQUEST: u64 = 512;

/// Defines the operations that a provider for the light subprotocol must fulfill.
pub trait Provider: Send + Sync {
	/// Provide current blockchain info.
	fn chain_info(&self) -> BlockChainInfo;

	/// Find the depth of a common ancestor between two blocks.
	/// If either block is unknown or an ancestor can't be found
	/// then return `None`.
	fn reorg_depth(&self, a: &H256, b: &H256) -> Option<u64>;

	/// Earliest block where state queries are available.
	/// If `None`, no state queries are servable.
	fn earliest_state(&self) -> Option<u64>;

	/// Provide a list of headers starting at the requested block,
	/// possibly in reverse and skipping `skip` at a time.
	///
	/// The returned vector may have any length in the range [0, `max`], but the
	/// results within must adhere to the `skip` and `reverse` parameters.
	fn block_headers(&self, req: request::header::CompleteRequest) -> Option<request::header::Response> {
		use request::HashOrNumber;

		if req.max == 0 { return None }

		let best_num = self.chain_info().best_block_number;
		let start_num = match req.start {
			HashOrNumber::Number(start_num) => start_num,
			HashOrNumber::Hash(hash) => match self.block_header(BlockId::Hash(hash)) {
				None => {
					trace!(target: "pip_provider", "Unknown block hash {} requested", hash);
					return None;
				}
				Some(header) => {
					let num = header.number();
					let canon_hash = self.block_header(BlockId::Number(num))
						.map(|h| h.hash());

					if req.max == 1 || canon_hash != Some(hash) {
						// Non-canonical header or single header requested.
						return Some(::request::header::Response {
							headers: vec![header],
						})
					}

					num
				}
			}
		};

		let max = ::std::cmp::min(MAX_HEADERS_PER_REQUEST, req.max);

		let headers: Vec<_> = (0_u64..max)
			.map(|x: u64| x.saturating_mul(req.skip.saturating_add(1)))
			.take_while(|&x| if req.reverse { x < start_num } else { best_num.saturating_sub(start_num) >= x })
			.map(|x| if req.reverse { start_num.saturating_sub(x) } else { start_num.saturating_add(x) })
			.map(|x| self.block_header(BlockId::Number(x)))
			.take_while(|x| x.is_some())
			.flat_map(|x| x)
			.collect();

		if headers.is_empty() {
			None
		} else {
			Some(::request::header::Response { headers })
		}
	}

	/// Get a block header by id.
	fn block_header(&self, id: BlockId) -> Option<encoded::Header>;

	/// Get a transaction index by hash.
	fn transaction_index(&self, req: request::transaction_index::CompleteRequest)
						 -> Option<request::transaction_index::Response>;

	/// Fulfill a block body request.
	fn block_body(&self, req: request::block_body::CompleteRequest) -> Option<request::block_body::Response>;

	/// Fulfill a request for block receipts.
	fn block_receipts(&self, req: request::block_receipts::CompleteRequest) -> Option<request::block_receipts::Response>;

	/// Get an account proof.
	fn account_proof(&self, req: request::account::CompleteRequest) -> Option<request::account::Response>;

	/// Get a storage proof.
	fn storage_proof(&self, req: request::storage::CompleteRequest) -> Option<request::storage::Response>;

	/// Provide contract code for the specified (block_hash, code_hash) pair.
	fn contract_code(&self, req: request::contract_code::CompleteRequest) -> Option<request::contract_code::Response>;

	/// Provide a header proof from a given Canonical Hash Trie as well as the
	/// corresponding header.
	fn header_proof(&self, req: request::header_proof::CompleteRequest) -> Option<request::header_proof::Response>;

	/// Provide pending transactions.
	fn transactions_to_propagate(&self) -> Vec<PendingTransaction>;

	/// Provide a proof-of-execution for the given transaction proof request.
	/// Returns a vector of all state items necessary to execute the transaction.
	fn transaction_proof(&self, req: request::execution::CompleteRequest) -> Option<request::execution::Response>;

	/// Provide epoch signal data at given block hash. This should be just the
	fn epoch_signal(&self, req: request::epoch_signal::CompleteRequest) -> Option<request::epoch_signal::Response>;
}

// Implementation of a light client data provider for a client.
impl<T: ProvingBlockChainClient + ?Sized> Provider for T {
	fn chain_info(&self) -> BlockChainInfo {
		ChainInfo::chain_info(self)
	}

	fn reorg_depth(&self, a: &H256, b: &H256) -> Option<u64> {
		self.tree_route(a, b).map(|route| route.index as u64)
	}

	fn earliest_state(&self) -> Option<u64> {
		Some(self.pruning_info().earliest_state)
	}

	fn block_header(&self, id: BlockId) -> Option<encoded::Header> {
		ClientBlockInfo::block_header(self, id)
	}

	fn transaction_index(&self, req: request::transaction_index::CompleteRequest)
						 -> Option<request::transaction_index::Response>
	{
		use common_types::ids::TransactionId;

		self.transaction_receipt(TransactionId::Hash(req.hash)).map(|receipt| request::transaction_index::Response {
			num: receipt.block_number,
			hash: receipt.block_hash,
			index: receipt.transaction_index as u64,
		})
	}

	fn block_body(&self, req: request::block_body::CompleteRequest) -> Option<request::block_body::Response> {
		BlockChainClient::block_body(self, BlockId::Hash(req.hash))
			.map(|body| ::request::block_body::Response { body })
	}

	fn block_receipts(&self, req: request::block_receipts::CompleteRequest) -> Option<request::block_receipts::Response> {
		BlockChainClient::block_receipts(self, &req.hash)
			.map(|x| ::request::block_receipts::Response { receipts: x.receipts })
	}

	fn account_proof(&self, req: request::account::CompleteRequest) -> Option<request::account::Response> {
		self.prove_account(req.address_hash, BlockId::Hash(req.block_hash)).map(|(proof, acc)| {
			::request::account::Response {
				proof,
				nonce: acc.nonce,
				balance: acc.balance,
				code_hash: acc.code_hash,
				storage_root: acc.storage_root,
			}
		})
	}

	fn storage_proof(&self, req: request::storage::CompleteRequest) -> Option<request::storage::Response> {
		self.prove_storage(req.address_hash, req.key_hash, BlockId::Hash(req.block_hash)).map(|(proof, item) | {
			::request::storage::Response {
				proof,
				value: item,
			}
		})
	}

	fn contract_code(&self, req: request::contract_code::CompleteRequest) -> Option<request::contract_code::Response> {
		self.state_data(&req.code_hash)
			.map(|code| ::request::contract_code::Response { code })
	}

	fn header_proof(&self, req: request::header_proof::CompleteRequest) -> Option<request::header_proof::Response> {
		let cht_number = match cht::block_to_cht_number(req.num) {
			Some(cht_num) => cht_num,
			None => {
				debug!(target: "pip_provider", "Requested CHT proof with invalid block number");
				return None;
			}
		};

		let mut needed = None;

		// build the CHT, caching the requested header as we pass through it.
		let cht = {
			let block_info = |id| {
				let hdr = self.block_header(id);
				let td = self.block_total_difficulty(id);

				match (hdr, td) {
					(Some(hdr), Some(td)) => {
						let info = BlockInfo {
							hash: hdr.hash(),
							parent_hash: hdr.parent_hash(),
							total_difficulty: td,
						};

						if hdr.number() == req.num {
							needed = Some((hdr, td));
						}

						Some(info)
					}
					_ => None,
				}
			};

			match cht::build(cht_number, block_info) {
				Some(cht) => cht,
				None => return None, // incomplete CHT.
			}
		};

		let (needed_hdr, needed_td) = needed.expect("`needed` always set in loop, number checked before; qed");

		// prove our result.
		match cht.prove(req.num, 0) {
			Ok(Some(proof)) => Some(::request::header_proof::Response {
				proof,
				hash: needed_hdr.hash(),
				td: needed_td,
			}),
			Ok(None) => None,
			Err(e) => {
				debug!(target: "pip_provider", "Error looking up number in freshly-created CHT: {}", e);
				None
			}
		}
	}

	fn transaction_proof(&self, req: request::execution::CompleteRequest) -> Option<request::execution::Response> {
		use common_types::transaction::Transaction;

		let id = BlockId::Hash(req.block_hash);
		let nonce = match self.nonce(&req.from, id) {
			Some(nonce) => nonce,
			None => return None,
		};
		let transaction = Transaction {
			nonce,
			gas: req.gas,
			gas_price: req.gas_price,
			action: req.action,
			value: req.value,
			data: req.data,
		}.fake_sign(req.from);

		self.prove_transaction(transaction, id)
			.map(|(_, proof)| ::request::execution::Response { items: proof })
	}

	fn transactions_to_propagate(&self) -> Vec<PendingTransaction> {
		BlockChainClient::transactions_to_propagate(self)
			.into_iter()
			.map(|tx| tx.pending().clone())
			.collect()
	}

	fn epoch_signal(&self, req: request::epoch_signal::CompleteRequest) -> Option<request::epoch_signal::Response> {
		self.epoch_signal(req.block_hash).map(|signal| request::epoch_signal::Response {
			signal,
		})
	}
}

/// The light client "provider" implementation. This wraps a `LightClient` and
/// a light transaction queue.
pub struct LightProvider<L> {
	client: Arc<L>,
	txqueue: Arc<RwLock<TransactionQueue>>,
}

impl<L> LightProvider<L> {
	/// Create a new `LightProvider` from the given client and transaction queue.
	pub fn new(client: Arc<L>, txqueue: Arc<RwLock<TransactionQueue>>) -> Self {
		LightProvider {
			client,
			txqueue,
		}
	}
}

// TODO: draw from cache (shared between this and the RPC layer)
impl<L: AsLightClient + Send + Sync> Provider for LightProvider<L> {
	fn chain_info(&self) -> BlockChainInfo {
		self.client.as_light_client().chain_info()
	}

	fn reorg_depth(&self, _a: &H256, _b: &H256) -> Option<u64> {
		None
	}

	fn earliest_state(&self) -> Option<u64> {
		None
	}

	fn block_header(&self, id: BlockId) -> Option<encoded::Header> {
		self.client.as_light_client().block_header(id)
	}

	fn transaction_index(&self, _req: request::transaction_index::CompleteRequest)
						 -> Option<request::transaction_index::Response>
	{
		None
	}

	fn block_body(&self, _req: request::block_body::CompleteRequest) -> Option<request::block_body::Response> {
		None
	}

	fn block_receipts(&self, _req: request::block_receipts::CompleteRequest) -> Option<request::block_receipts::Response> {
		None
	}

	fn account_proof(&self, _req: request::account::CompleteRequest) -> Option<request::account::Response> {
		None
	}

	fn storage_proof(&self, _req: request::storage::CompleteRequest) -> Option<request::storage::Response> {
		None
	}

	fn contract_code(&self, _req: request::contract_code::CompleteRequest) -> Option<request::contract_code::Response> {
		None
	}

	fn header_proof(&self, _req: request::header_proof::CompleteRequest) -> Option<request::header_proof::Response> {
		None
	}

	fn transaction_proof(&self, _req: request::execution::CompleteRequest) -> Option<request::execution::Response> {
		None
	}

	fn epoch_signal(&self, _req: request::epoch_signal::CompleteRequest) -> Option<request::epoch_signal::Response> {
		None
	}

	fn transactions_to_propagate(&self) -> Vec<PendingTransaction> {
		let chain_info = self.chain_info();
		self.txqueue.read()
			.ready_transactions(chain_info.best_block_number, chain_info.best_block_timestamp)
	}
}

impl<L: AsLightClient> AsLightClient for LightProvider<L> {
	type Client = L::Client;

	fn as_light_client(&self) -> &L::Client {
		self.client.as_light_client()
	}
}

#[cfg(test)]
mod tests {
	use ethcore::client::{EachBlockWith, TestBlockChainClient};
	use super::Provider;

	#[test]
	fn cht_proof() {
		let client = TestBlockChainClient::new();
		client.add_blocks(2000, EachBlockWith::Nothing);

		let req = ::request::header_proof::CompleteRequest {
			num: 1500,
		};

		assert!(client.header_proof(req.clone()).is_none());

		client.add_blocks(48, EachBlockWith::Nothing);

		assert!(client.header_proof(req.clone()).is_some());
	}
}
