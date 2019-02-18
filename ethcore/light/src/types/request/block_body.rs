//! block_body
use super::{Field, NoSuchOutput, OutputKind, Output};
use common_types::encoded;
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};
use ethereum_types::H256;

/// Potentially incomplete block body request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteRequest {
	/// Block hash to get receipts for.
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

	fn note_outputs<F>(&self, _: F) where F: FnMut(usize, OutputKind) {}

	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput> {
		if let Field::BackReference(req, idx) = self.hash {
			self.hash = match oracle(req, idx) {
				Ok(Output::Hash(hash)) => Field::Scalar(hash),
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

/// A complete block body request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// The hash to get a block body for.
	pub hash: H256,
}

/// The output of a request for block body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
	/// The block body.
	pub body: encoded::Body,
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) {}
}

impl Decodable for Response {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		use common_types::header::Header as FullHeader;
		use common_types::transaction::UnverifiedTransaction;

		// check body validity.
		let _: Vec<UnverifiedTransaction> = rlp.list_at(0)?;
		let _: Vec<FullHeader> = rlp.list_at(1)?;

		Ok(Response {
			body: encoded::Body::new(rlp.as_raw().to_owned()),
		})
	}
}

impl Encodable for Response {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.append_raw(&self.body.rlp().as_raw(), 1);
	}
}
