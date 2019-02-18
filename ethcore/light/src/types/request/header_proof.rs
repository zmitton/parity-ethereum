//! header_proof

use super::{Field, NoSuchOutput, OutputKind, Output};
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};
use ethereum_types::{H256, U256};
use bytes::Bytes;

/// Potentially incomplete header proof request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteHeaderProofRequest {
	/// Block number.
	pub num: Field<u64>,
}

impl super::IncompleteRequest for IncompleteHeaderProofRequest {
	type Complete = CompleteHeaderProofRequest;
	type Response = HeaderProofResponse;

	fn check_outputs<F>(&self, mut f: F) -> Result<(), NoSuchOutput>
	where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>
	{
		match self.num {
			Field::Scalar(_) => Ok(()),
			Field::BackReference(req, idx) => f(req, idx, OutputKind::Number),
		}
	}

	fn note_outputs<F>(&self, mut note: F) where F: FnMut(usize, OutputKind) {
		note(0, OutputKind::Hash);
	}

	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput> {
		if let Field::BackReference(req, idx) = self.num {
			self.num = match oracle(req, idx) {
				Ok(Output::Number(num)) => Field::Scalar(num),
				_ => Field::BackReference(req, idx),
			}
		}
	}

	fn complete(self) -> Result<Self::Complete, NoSuchOutput> {
		Ok(CompleteHeaderProofRequest {
			num: self.num.into_scalar()?,
		})
	}

	fn adjust_refs<F>(&mut self, mapping: F) where F: FnMut(usize) -> usize {
		self.num.adjust_req(mapping)
	}
}

/// A complete header proof request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteHeaderProofRequest {
	/// The number to get a header proof for.
	pub num: u64,
}

/// The output of a request for a header proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderProofResponse {
	/// Inclusion proof of the header and total difficulty in the CHT.
	pub proof: Vec<Bytes>,
	/// The proved header's hash.
	pub hash: H256,
	/// The proved header's total difficulty.
	pub td: U256,
}

impl super::ResponseLike for HeaderProofResponse {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, mut f: F) where F: FnMut(usize, Output) {
		f(0, Output::Hash(self.hash));
	}
}

impl Decodable for HeaderProofResponse {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(HeaderProofResponse {
			proof: rlp.list_at(0)?,
			hash: rlp.val_at(1)?,
			td: rlp.val_at(2)?,
		})
	}
}

impl Encodable for HeaderProofResponse {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(3)
			.append_list::<Vec<u8>,_>(&self.proof[..])
			.append(&self.hash)
			.append(&self.td);
	}
}
