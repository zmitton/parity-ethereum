//! contract_code
use super::{Field, NoSuchOutput, OutputKind, Output};
use ethereum_types::H256;
use bytes::Bytes;

/// Potentially incomplete contract code request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteCodeRequest {
	/// The block hash to request the state for.
	pub block_hash: Field<H256>,
	/// The code hash.
	pub code_hash: Field<H256>,
}

impl super::IncompleteRequest for IncompleteCodeRequest {
	type Complete = CompleteCodeRequest;
	type Response = CodeResponse;

	fn check_outputs<F>(&self, mut f: F) -> Result<(), NoSuchOutput>
	where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>
	{
		if let Field::BackReference(req, idx) = self.block_hash {
			f(req, idx, OutputKind::Hash)?;
		}
		if let Field::BackReference(req, idx) = self.code_hash {
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

		if let Field::BackReference(req, idx) = self.code_hash {
			self.code_hash = match oracle(req, idx) {
				Ok(Output::Hash(code_hash)) => Field::Scalar(code_hash),
				_ => Field::BackReference(req, idx),
			}
		}
	}

	fn complete(self) -> Result<Self::Complete, NoSuchOutput> {
		Ok(CompleteCodeRequest {
			block_hash: self.block_hash.into_scalar()?,
			code_hash: self.code_hash.into_scalar()?,
		})
	}

	fn adjust_refs<F>(&mut self, mut mapping: F) where F: FnMut(usize) -> usize {
		self.block_hash.adjust_req(&mut mapping);
		self.code_hash.adjust_req(&mut mapping);
	}
}

/// A complete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCodeRequest {
	/// The block hash to request the state for.
	pub block_hash: H256,
	/// The code hash.
	pub code_hash: H256,
}

/// The output of a request for
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodableWrapper, RlpDecodableWrapper)]
pub struct CodeResponse {
	/// The requested code.
	pub code: Bytes,
}

impl super::ResponseLike for CodeResponse {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) {}
}
