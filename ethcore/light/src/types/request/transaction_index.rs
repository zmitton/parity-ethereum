//! transaction_index

use super::{Field, NoSuchOutput, OutputKind, Output};
use ethereum_types::H256;

/// Potentially incomplete transaction index request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteRequest {
	/// Transaction hash to get index for.
	pub hash: Field<H256>,
}

impl super::IncompleteRequest for IncompleteRequest {
	type Complete = CompleteRequest;
	type Response = Response;

	fn check_outputs<F>(&self, mut f: F) -> Result<(), NoSuchOutput>
	where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>
	{
		match self.hash {
			Field::Scalar(_) => Ok(()),
			Field::BackReference(req, idx) => f(req, idx, OutputKind::Hash),
		}
	}

	fn note_outputs<F>(&self, mut f: F) where F: FnMut(usize, OutputKind) {
		f(0, OutputKind::Number);
		f(1, OutputKind::Hash);
	}

	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput> {
		if let Field::BackReference(req, idx) = self.hash {
			self.hash = match oracle(req, idx) {
				Ok(Output::Number(hash)) => Field::Scalar(hash.into()),
				_ => Field::BackReference(req, idx),
			}
		}
	}

	fn complete(self) -> Result<Self::Complete, NoSuchOutput> {
		Ok(CompleteRequest {
			hash: self.hash.into_scalar()?,
		})
	}

	fn adjust_refs<F>(&mut self, mapping: F) where F: FnMut(usize) -> usize {
		self.hash.adjust_req(mapping)
	}
}

/// A complete transaction index request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// The transaction hash to get index for.
	pub hash: H256,
}

/// The output of a request for transaction index.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Response {
	/// Block number.
	pub num: u64,
	/// Block hash
	pub hash: H256,
	/// Index in block.
	pub index: u64,
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, mut f: F) where F: FnMut(usize, Output) {
		f(0, Output::Number(self.num));
		f(1, Output::Hash(self.hash));
	}
}
