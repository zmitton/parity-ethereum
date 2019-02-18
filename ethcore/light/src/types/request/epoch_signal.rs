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

//! Epoch signal requests

use super::{Field, NoSuchOutput, OutputKind, Output};
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};
use ethereum_types::H256;
use bytes::Bytes;

/// Potentially incomplete epoch signal request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompleteRequest {
	/// The block hash to request the signal for.
	pub block_hash: Field<H256>,
}

impl Decodable for IncompleteRequest {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(IncompleteRequest {
			block_hash: rlp.val_at(0)?,
		})
	}
}

impl Encodable for IncompleteRequest {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(1).append(&self.block_hash);
	}
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
		})
	}

	fn adjust_refs<F>(&mut self, mut mapping: F) where F: FnMut(usize) -> usize {
		self.block_hash.adjust_req(&mut mapping);
	}
}

/// A complete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// The block hash to request the epoch signal for.
	pub block_hash: H256,
}

/// The output of a request for an epoch signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
	/// The requested epoch signal.
	pub signal: Bytes,
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) {}
}

impl Decodable for Response {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {

		Ok(Response {
			signal: rlp.as_val()?,
		})
	}
}

impl Encodable for Response {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.append(&self.signal);
	}
}
