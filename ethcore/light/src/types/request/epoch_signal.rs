//! epoch_signal
use super::{Field, NoSuchOutput, OutputKind, Output};
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};
use ethereum_types::H256;
use bytes::Bytes;

/// Potentially incomplete epoch signal request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompleteSignalRequest {
	/// The block hash to request the signal for.
	pub block_hash: Field<H256>,
}

impl Decodable for IncompleteSignalRequest {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(IncompleteSignalRequest {
			block_hash: rlp.val_at(0)?,
		})
	}
}

impl Encodable for IncompleteSignalRequest {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(1).append(&self.block_hash);
	}
}

impl super::IncompleteRequest for IncompleteSignalRequest {
	type Complete = CompleteSignalRequest;
	type Response = SignalResponse;

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
		Ok(CompleteSignalRequest {
			block_hash: self.block_hash.into_scalar()?,
		})
	}

	fn adjust_refs<F>(&mut self, mut mapping: F) where F: FnMut(usize) -> usize {
		self.block_hash.adjust_req(&mut mapping);
	}
}

/// A complete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteSignalRequest {
	/// The block hash to request the epoch signal for.
	pub block_hash: H256,
}

/// The output of a request for an epoch signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalResponse {
	/// The requested epoch signal.
	pub signal: Bytes,
}

impl super::ResponseLike for SignalResponse {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) {}
}

impl Decodable for SignalResponse {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {

		Ok(SignalResponse {
			signal: rlp.as_val()?,
		})
	}
}

impl Encodable for SignalResponse {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.append(&self.signal);
	}
}
