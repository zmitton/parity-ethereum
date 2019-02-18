//! account
use super::{Field, NoSuchOutput, OutputKind, Output};
use ethereum_types::{H256, U256};
use bytes::Bytes;

/// Potentially incomplete request for an account proof.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteRequest {
	/// Block hash to request state proof for.
	pub block_hash: Field<H256>,
	/// Hash of the account's address.
	pub address_hash: Field<H256>,
}

impl super::IncompleteRequest for IncompleteRequest {
	type Complete = CompleteRequest;
	type Response = Response;

	fn check_outputs<F>(&self, mut f: F) -> Result<(), NoSuchOutput>
	where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>
	{
		if let Field::BackReference(req, idx) = self.block_hash {
			f(req, idx, OutputKind::Hash)?
		}

		if let Field::BackReference(req, idx) = self.address_hash {
			f(req, idx, OutputKind::Hash)?
		}

		Ok(())
	}

	fn note_outputs<F>(&self, mut f: F) where F: FnMut(usize, OutputKind) {
		f(0, OutputKind::Hash);
		f(1, OutputKind::Hash);
	}

	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput> {
		if let Field::BackReference(req, idx) = self.block_hash {
			self.block_hash = match oracle(req, idx) {
				Ok(Output::Hash(block_hash)) => Field::Scalar(block_hash),
				_ => Field::BackReference(req, idx),
			}
		}

		if let Field::BackReference(req, idx) = self.address_hash {
			self.address_hash = match oracle(req, idx) {
				Ok(Output::Hash(address_hash)) => Field::Scalar(address_hash),
				_ => Field::BackReference(req, idx),
			}
		}
	}

	fn complete(self) -> Result<Self::Complete, NoSuchOutput> {
		Ok(CompleteRequest {
			block_hash: self.block_hash.into_scalar()?,
			address_hash: self.address_hash.into_scalar()?,
		})
	}

	fn adjust_refs<F>(&mut self, mut mapping: F) where F: FnMut(usize) -> usize {
		self.block_hash.adjust_req(&mut mapping);
		self.address_hash.adjust_req(&mut mapping);
	}
}

/// A complete request for an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// Block hash to request state proof for.
	pub block_hash: H256,
	/// Hash of the account's address.
	pub address_hash: H256,
}

/// The output of a request for an account state proof.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Response {
	/// Inclusion/exclusion proof
	pub proof: Vec<Bytes>,
	/// Account nonce.
	pub nonce: U256,
	/// Account balance.
	pub balance: U256,
	/// Account's code hash.
	pub code_hash: H256,
	/// Account's storage trie root.
	pub storage_root: H256,
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, mut f: F) where F: FnMut(usize, Output) {
		f(0, Output::Hash(self.code_hash));
		f(1, Output::Hash(self.storage_root));
	}
}
