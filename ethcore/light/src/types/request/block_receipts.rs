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

//! Block body receipts

use super::{Field, NoSuchOutput, OutputKind, Output};
use common_types::receipt::Receipt;
use ethereum_types::H256;

/// Potentially incomplete block receipts request.
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

/// A complete block receipts request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteRequest {
	/// The number to get block receipts for.
	pub hash: H256,
}

/// The output of a request for block receipts.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodableWrapper, RlpDecodableWrapper)]
pub struct Response {
	/// The block receipts.
	pub receipts: Vec<Receipt>
}

impl super::ResponseLike for Response {
	/// Fill reusable outputs by providing them to the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) {}
}
