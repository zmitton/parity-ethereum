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

//! Header requests

use super::{Field, HashOrNumber, NoSuchOutput, OutputKind, Output};
use common_types::encoded;
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};

/// Potentially incomplete headers request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteRequest {
	/// Start block.
	pub start: Field<HashOrNumber>,
	/// Skip between.
	pub skip: u64,
	/// Maximum to return.
	pub max: u64,
	/// Whether to reverse from start.
	pub reverse: bool,
}

impl super::IncompleteRequest for IncompleteRequest {
	type Complete = CompleteRequest;
	type Response = Response;

	fn check_outputs<F>(&self, mut f: F) -> Result<(), NoSuchOutput>
	where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>
	{
		match self.start {
			Field::Scalar(_) => Ok(()),
			Field::BackReference(req, idx) =>
				f(req, idx, OutputKind::Hash).or_else(|_| f(req, idx, OutputKind::Number))
		}
	}

	fn note_outputs<F>(&self, _: F) where F: FnMut(usize, OutputKind) { }

	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput> {
		if let Field::BackReference(req, idx) = self.start {
			self.start = match oracle(req, idx) {
				Ok(Output::Hash(hash)) => Field::Scalar(hash.into()),
				Ok(Output::Number(num)) => Field::Scalar(num.into()),
				Err(_) => Field::BackReference(req, idx),
			}
		}
	}

	fn complete(self) -> Result<Self::Complete, NoSuchOutput> {
		Ok(CompleteRequest {
			start: self.start.into_scalar()?,
			skip: self.skip,
			max: self.max,
			reverse: self.reverse,
		})
	}

	fn adjust_refs<F>(&mut self, mapping: F) where F: FnMut(usize) -> usize {
		self.start.adjust_req(mapping)
	}
}

/// A complete header request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// Start block.
	pub start: HashOrNumber,
	/// Skip between.
	pub skip: u64,
	/// Maximum to return.
	pub max: u64,
	/// Whether to reverse from start.
	pub reverse: bool,
}

/// The output of a request for headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
	/// The headers requested.
	pub headers: Vec<encoded::Header>,
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by writing them into the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) { }
}

impl Decodable for Response {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		use common_types::header::Header as FullHeader;

		let mut headers = Vec::new();

		for item in rlp.iter() {
			// check that it's a valid encoding.
			// TODO: just return full headers here?
			let _: FullHeader = item.as_val()?;
			headers.push(encoded::Header::new(item.as_raw().to_owned()));
		}

		Ok(Response { headers })
	}
}

impl Encodable for Response {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(self.headers.len());
		for header in &self.headers {
			s.append_raw(header.rlp().as_raw(), 1);
		}
	}
}
