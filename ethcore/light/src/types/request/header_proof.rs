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

//! Header proof requests

use super::{Field, NoSuchOutput, OutputKind, Output};
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};
use ethereum_types::{H256, U256};
use bytes::Bytes;

/// Potentially incomplete header proof request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteRequest {
	/// Block number.
	pub num: Field<u64>,
}

impl super::IncompleteRequest for IncompleteRequest {
	type Complete = CompleteRequest;
	type Response = Response;

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
		Ok(CompleteRequest {
			num: self.num.into_scalar()?,
		})
	}

	fn adjust_refs<F>(&mut self, mapping: F) where F: FnMut(usize) -> usize {
		self.num.adjust_req(mapping)
	}
}

/// A complete header proof request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// The number to get a header proof for.
	pub num: u64,
}

/// The output of a request for a header proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
	/// Inclusion proof of the header and total difficulty in the CHT.
	pub proof: Vec<Bytes>,
	/// The proved header's hash.
	pub hash: H256,
	/// The proved header's total difficulty.
	pub td: U256,
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, mut f: F) where F: FnMut(usize, Output) {
		f(0, Output::Hash(self.hash));
	}
}

impl Decodable for Response {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(Response {
			proof: rlp.list_at(0)?,
			hash: rlp.val_at(1)?,
			td: rlp.val_at(2)?,
		})
	}
}

impl Encodable for Response {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(3)
			.append_list::<Vec<u8>,_>(&self.proof[..])
			.append(&self.hash)
			.append(&self.td);
	}
}
