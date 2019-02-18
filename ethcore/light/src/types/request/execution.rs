//! execution
use super::{Field, NoSuchOutput, OutputKind, Output};
use common_types::transaction::Action;
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};
use ethereum_types::{H256, U256, Address};
use kvdb::DBValue;
use bytes::Bytes;

/// Potentially incomplete execution proof request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteRequest {
	/// The block hash to request the state for.
	pub block_hash: Field<H256>,
	/// The address the transaction should be from.
	pub from: Address,
	/// The action of the transaction.
	pub action: Action,
	/// The amount of gas to prove.
	pub gas: U256,
	/// The gas price.
	pub gas_price: U256,
	/// The value to transfer.
	pub value: U256,
	/// Call data.
	pub data: Bytes,
}

impl super::IncompleteRequest for IncompleteRequest {
	type Complete = CompleteRequest;
	type Response = Response;

	fn check_outputs<F>(&self, mut f: F) -> Result<(), NoSuchOutput>
	where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>
	{
		if let Field::BackReference(req, idx) = self.block_hash {
			f(req, idx, OutputKind::Hash)?;
		}

		Ok(())
	}

	fn note_outputs<F>(&self, _: F) where F: FnMut(usize, OutputKind) {}

	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput> {
		if let Field::BackReference(req, idx) = self.block_hash {
			self.block_hash = match oracle(req, idx) {
				Ok(Output::Hash(block_hash)) => Field::Scalar(block_hash),
				_ => Field::BackReference(req, idx),
			}
		}
	}
	fn complete(self) -> Result<Self::Complete, NoSuchOutput> {
		Ok(CompleteRequest {
			block_hash: self.block_hash.into_scalar()?,
			from: self.from,
			action: self.action,
			gas: self.gas,
			gas_price: self.gas_price,
			value: self.value,
			data: self.data,
		})
	}

	fn adjust_refs<F>(&mut self, mapping: F) where F: FnMut(usize) -> usize {
		self.block_hash.adjust_req(mapping);
	}
}

/// A complete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// The block hash to request the state for.
	pub block_hash: H256,
	/// The address the transaction should be from.
	pub from: Address,
	/// The action of the transaction.
	pub action: Action,
	/// The amount of gas to prove.
	pub gas: U256,
	/// The gas price.
	pub gas_price: U256,
	/// The value to transfer.
	pub value: U256,
	/// Call data.
	pub data: Bytes,
}

/// The output of a request for proof of execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
	/// All state items (trie nodes, code) necessary to re-prove the transaction.
	pub items: Vec<DBValue>,
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) {}
}

impl Decodable for Response {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let mut items = Vec::new();
		for raw_item in rlp.iter() {
			let mut item = DBValue::new();
			item.append_slice(raw_item.data()?);
			items.push(item);
		}

		Ok(Response { items })
	}
}

impl Encodable for Response {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(self.items.len());

		for item in &self.items {
			s.append(&&**item);
		}
	}
}
