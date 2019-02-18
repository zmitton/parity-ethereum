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

//! Light protocol request types.

use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};
use ethereum_types::H256;

mod batch;
pub mod account;
pub mod block_body;
pub mod block_receipts;
pub mod contract_code;
pub mod epoch_signal;
pub mod execution;
pub mod header;
pub mod header_proof;
pub mod storage;
pub mod transaction_index;

pub use self::batch::{Batch, Builder};

/// Error indicating a reference to a non-existent or wrongly-typed output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSuchOutput;

/// Wrong kind of response corresponding to request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrongKind;

/// Error on processing a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseError<T> {
	/// Error in validity.
	Validity(T),
	/// No responses expected.
	Unexpected,
}

/// An input to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field<T> {
	/// A pre-specified input.
	Scalar(T),
	/// An input which can be resolved later on.
	/// (Request index, output index)
	BackReference(usize, usize),
}

impl<T> Field<T> {
	/// Helper for creating a new back-reference field.
	pub fn back_ref(idx: usize, req: usize) -> Self {
		Field::BackReference(idx, req)
	}

	/// map a scalar into some other item.
	pub fn map<F, U>(self, f: F) -> Field<U> where F: FnOnce(T) -> U {
		match self {
			Field::Scalar(x) => Field::Scalar(f(x)),
			Field::BackReference(req, idx) => Field::BackReference(req, idx),
		}
	}

	/// Attempt to get a reference to the inner scalar.
	pub fn as_ref(&self) -> Option<&T> {
		match *self {
			Field::Scalar(ref x) => Some(x),
			Field::BackReference(_, _) => None,
		}
	}

	// attempt conversion into scalar value.
	fn into_scalar(self) -> Result<T, NoSuchOutput> {
		match self {
			Field::Scalar(val) => Ok(val),
			_ => Err(NoSuchOutput),
		}
	}

	fn adjust_req<F>(&mut self, mut mapping: F) where F: FnMut(usize) -> usize {
		if let Field::BackReference(ref mut req_idx, _) = *self {
			*req_idx = mapping(*req_idx)
		}
	}
}

impl<T> From<T> for Field<T> {
	fn from(val: T) -> Self {
		Field::Scalar(val)
	}
}

impl<T: Decodable> Decodable for Field<T> {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		match rlp.val_at::<u8>(0)? {
			0 => Ok(Field::Scalar(rlp.val_at::<T>(1)?)),
			1 => Ok({
				let inner_rlp = rlp.at(1)?;
				Field::BackReference(inner_rlp.val_at(0)?, inner_rlp.val_at(1)?)
			}),
			_ => Err(DecoderError::Custom("Unknown discriminant for PIP field.")),
		}
	}
}

impl<T: Encodable> Encodable for Field<T> {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2);
		match *self {
			Field::Scalar(ref data) => {
				s.append(&0u8).append(data);
			}
			Field::BackReference(ref req, ref idx) => {
				s.append(&1u8).begin_list(2).append(req).append(idx);
			}
		}
	}
}

/// Request outputs which can be reused as inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
	/// A 32-byte hash output.
	Hash(H256),
	/// An unsigned-integer output.
	Number(u64),
}

impl Output {
	/// Get the output kind.
	pub fn kind(&self) -> OutputKind {
		match *self {
			Output::Hash(_) => OutputKind::Hash,
			Output::Number(_) => OutputKind::Number,
		}
	}
}

/// Response output kinds which can be used as back-references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputKind {
	/// A 32-byte hash output.
	Hash,
	/// An unsigned-integer output.
	Number,
}

/// Either a hash or a number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOrNumber {
	/// Block hash variant.
	Hash(H256),
	/// Block number variant.
	Number(u64),
}

impl From<H256> for HashOrNumber {
	fn from(hash: H256) -> Self {
		HashOrNumber::Hash(hash)
	}
}

impl From<u64> for HashOrNumber {
	fn from(num: u64) -> Self {
		HashOrNumber::Number(num)
	}
}

impl Decodable for HashOrNumber {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		rlp.as_val::<H256>().map(HashOrNumber::Hash)
			.or_else(|_| rlp.as_val().map(HashOrNumber::Number))
	}
}

impl Encodable for HashOrNumber {
	fn rlp_append(&self, s: &mut RlpStream) {
		match *self {
			HashOrNumber::Hash(ref hash) => s.append(hash),
			HashOrNumber::Number(ref num) => s.append(num),
		};
	}
}

/// Type alias for "network requests".
pub type NetworkRequests = Batch<Request>;

/// All request types, as they're sent over the network.
/// They may be incomplete, with back-references to outputs
/// of prior requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
	/// A request for block headers.
	Headers(header::IncompleteRequest),
	/// A request for a header proof (from a CHT)
	HeaderProof(header_proof::IncompleteRequest),
	/// A request for a transaction index by hash.
	TransactionIndex(transaction_index::IncompleteRequest),
	/// A request for a block's receipts.
	Receipts(block_receipts::IncompleteRequest),
	/// A request for a block body.
	Body(block_body::IncompleteRequest),
	/// A request for a merkle proof of an account.
	Account(account::IncompleteRequest),
	/// A request for a merkle proof of contract storage.
	Storage(storage::IncompleteRequest),
	/// A request for contract code.
	Code(contract_code::IncompleteRequest),
	/// A request for proof of execution,
	Execution(execution::IncompleteRequest),
	/// A request for an epoch signal.
	Signal(epoch_signal::IncompleteRequest),
}

/// All request types, in an answerable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompleteRequest {
	/// A request for block headers.
	Headers(header::CompleteRequest),
	/// A request for a header proof (from a CHT)
	HeaderProof(header_proof::CompleteRequest),
	/// A request for a transaction index by hash.
	TransactionIndex(transaction_index::CompleteRequest),
	/// A request for a block's receipts.
	Receipts(block_receipts::CompleteRequest),
	/// A request for a block body.
	Body(block_body::CompleteRequest),
	/// A request for a merkle proof of an account.
	Account(account::CompleteRequest),
	/// A request for a merkle proof of contract storage.
	Storage(storage::CompleteRequest),
	/// A request for contract code.
	Code(contract_code::CompleteRequest),
	/// A request for proof of execution,
	Execution(execution::CompleteRequest),
	/// A request for an epoch signal.
	Signal(epoch_signal::CompleteRequest),
}

impl CompleteRequest {
	/// Inspect the kind of this response.
	pub fn kind(&self) -> Kind {
		match *self {
			CompleteRequest::Headers(_) => Kind::Headers,
			CompleteRequest::HeaderProof(_) => Kind::HeaderProof,
			CompleteRequest::TransactionIndex(_) => Kind::TransactionIndex,
			CompleteRequest::Receipts(_) => Kind::Receipts,
			CompleteRequest::Body(_) => Kind::Body,
			CompleteRequest::Account(_) => Kind::Account,
			CompleteRequest::Storage(_) => Kind::Storage,
			CompleteRequest::Code(_) => Kind::Code,
			CompleteRequest::Execution(_) => Kind::Execution,
			CompleteRequest::Signal(_) => Kind::Signal,
		}
	}
}

impl Request {
	/// Get the request kind.
	pub fn kind(&self) -> Kind {
		match *self {
			Request::Headers(_) => Kind::Headers,
			Request::HeaderProof(_) => Kind::HeaderProof,
			Request::TransactionIndex(_) => Kind::TransactionIndex,
			Request::Receipts(_) => Kind::Receipts,
			Request::Body(_) => Kind::Body,
			Request::Account(_) => Kind::Account,
			Request::Storage(_) => Kind::Storage,
			Request::Code(_) => Kind::Code,
			Request::Execution(_) => Kind::Execution,
			Request::Signal(_) => Kind::Signal,
		}
	}
}

impl Decodable for Request {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		match rlp.val_at::<Kind>(0)? {
			Kind::Headers => Ok(Request::Headers(rlp.val_at(1)?)),
			Kind::HeaderProof => Ok(Request::HeaderProof(rlp.val_at(1)?)),
			Kind::TransactionIndex => Ok(Request::TransactionIndex(rlp.val_at(1)?)),
			Kind::Receipts => Ok(Request::Receipts(rlp.val_at(1)?)),
			Kind::Body => Ok(Request::Body(rlp.val_at(1)?)),
			Kind::Account => Ok(Request::Account(rlp.val_at(1)?)),
			Kind::Storage => Ok(Request::Storage(rlp.val_at(1)?)),
			Kind::Code => Ok(Request::Code(rlp.val_at(1)?)),
			Kind::Execution => Ok(Request::Execution(rlp.val_at(1)?)),
			Kind::Signal => Ok(Request::Signal(rlp.val_at(1)?)),
		}
	}
}

impl Encodable for Request {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2);

		// hack around https://github.com/paritytech/parity-ethereum/issues/4356
		Encodable::rlp_append(&self.kind(), s);

		match *self {
			Request::Headers(ref req) => s.append(req),
			Request::HeaderProof(ref req) => s.append(req),
			Request::TransactionIndex(ref req) => s.append(req),
			Request::Receipts(ref req) => s.append(req),
			Request::Body(ref req) => s.append(req),
			Request::Account(ref req) => s.append(req),
			Request::Storage(ref req) => s.append(req),
			Request::Code(ref req) => s.append(req),
			Request::Execution(ref req) => s.append(req),
			Request::Signal(ref req) => s.append(req),
		};
	}
}

impl IncompleteRequest for Request {
	type Complete = CompleteRequest;
	type Response = Response;

	fn check_outputs<F>(&self, f: F) -> Result<(), NoSuchOutput>
		where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>
	{
		match *self {
			Request::Headers(ref req) => req.check_outputs(f),
			Request::HeaderProof(ref req) => req.check_outputs(f),
			Request::TransactionIndex(ref req) => req.check_outputs(f),
			Request::Receipts(ref req) => req.check_outputs(f),
			Request::Body(ref req) => req.check_outputs(f),
			Request::Account(ref req) => req.check_outputs(f),
			Request::Storage(ref req) => req.check_outputs(f),
			Request::Code(ref req) => req.check_outputs(f),
			Request::Execution(ref req) => req.check_outputs(f),
			Request::Signal(ref req) => req.check_outputs(f),
		}
	}

	fn note_outputs<F>(&self, f: F) where F: FnMut(usize, OutputKind) {
		match *self {
			Request::Headers(ref req) => req.note_outputs(f),
			Request::HeaderProof(ref req) => req.note_outputs(f),
			Request::TransactionIndex(ref req) => req.note_outputs(f),
			Request::Receipts(ref req) => req.note_outputs(f),
			Request::Body(ref req) => req.note_outputs(f),
			Request::Account(ref req) => req.note_outputs(f),
			Request::Storage(ref req) => req.note_outputs(f),
			Request::Code(ref req) => req.note_outputs(f),
			Request::Execution(ref req) => req.note_outputs(f),
			Request::Signal(ref req) => req.note_outputs(f),
		}
	}

	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput> {
		match *self {
			Request::Headers(ref mut req) => req.fill(oracle),
			Request::HeaderProof(ref mut req) => req.fill(oracle),
			Request::TransactionIndex(ref mut req) => req.fill(oracle),
			Request::Receipts(ref mut req) => req.fill(oracle),
			Request::Body(ref mut req) => req.fill(oracle),
			Request::Account(ref mut req) => req.fill(oracle),
			Request::Storage(ref mut req) => req.fill(oracle),
			Request::Code(ref mut req) => req.fill(oracle),
			Request::Execution(ref mut req) => req.fill(oracle),
			Request::Signal(ref mut req) => req.fill(oracle),
		}
	}

	fn complete(self) -> Result<Self::Complete, NoSuchOutput> {
		match self {
			Request::Headers(req) => req.complete().map(CompleteRequest::Headers),
			Request::HeaderProof(req) => req.complete().map(CompleteRequest::HeaderProof),
			Request::TransactionIndex(req) => req.complete().map(CompleteRequest::TransactionIndex),
			Request::Receipts(req) => req.complete().map(CompleteRequest::Receipts),
			Request::Body(req) => req.complete().map(CompleteRequest::Body),
			Request::Account(req) => req.complete().map(CompleteRequest::Account),
			Request::Storage(req) => req.complete().map(CompleteRequest::Storage),
			Request::Code(req) => req.complete().map(CompleteRequest::Code),
			Request::Execution(req) => req.complete().map(CompleteRequest::Execution),
			Request::Signal(req) => req.complete().map(CompleteRequest::Signal),
		}
	}

	fn adjust_refs<F>(&mut self, mapping: F) where F: FnMut(usize) -> usize {
		match *self {
			Request::Headers(ref mut req) => req.adjust_refs(mapping),
			Request::HeaderProof(ref mut req) => req.adjust_refs(mapping),
			Request::TransactionIndex(ref mut req) => req.adjust_refs(mapping),
			Request::Receipts(ref mut req) => req.adjust_refs(mapping),
			Request::Body(ref mut req) => req.adjust_refs(mapping),
			Request::Account(ref mut req) => req.adjust_refs(mapping),
			Request::Storage(ref mut req) => req.adjust_refs(mapping),
			Request::Code(ref mut req) => req.adjust_refs(mapping),
			Request::Execution(ref mut req) => req.adjust_refs(mapping),
			Request::Signal(ref mut req) => req.adjust_refs(mapping),
		}
	}
}

impl CheckedRequest for Request {
	type Extract = ();
	type Error = WrongKind;
	type Environment = ();

	fn check_response(&self, _: &Self::Complete, _: &(), response: &Response) -> Result<(), WrongKind> {
		if self.kind() == response.kind() {
			Ok(())
		} else {
			Err(WrongKind)
		}
	}
}

/// Kinds of requests.
/// Doubles as the "ID" field of the request.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
	/// A request for headers.
	Headers = 0,
	/// A request for a header proof.
	HeaderProof = 1,
	/// A request for a transaction index.
	TransactionIndex = 2,
	/// A request for block receipts.
	Receipts = 3,
	/// A request for a block body.
	Body = 4,
	/// A request for an account + merkle proof.
	Account = 5,
	/// A request for contract storage + merkle proof
	Storage = 6,
	/// A request for contract.
	Code = 7,
	/// A request for transaction execution + state proof.
	Execution = 8,
	/// A request for epoch transition signal.
	Signal = 9,
}

impl Decodable for Kind {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		match rlp.as_val::<u8>()? {
			0 => Ok(Kind::Headers),
			1 => Ok(Kind::HeaderProof),
			2 => Ok(Kind::TransactionIndex),
			3 => Ok(Kind::Receipts),
			4 => Ok(Kind::Body),
			5 => Ok(Kind::Account),
			6 => Ok(Kind::Storage),
			7 => Ok(Kind::Code),
			8 => Ok(Kind::Execution),
			9 => Ok(Kind::Signal),
			_ => Err(DecoderError::Custom("Unknown PIP request ID.")),
		}
	}
}

impl Encodable for Kind {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.append(&(*self as u8));
	}
}

/// All response types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
	/// A response for block headers.
	Headers(header::Response),
	/// A response for a header proof (from a CHT)
	HeaderProof(header_proof::Response),
	/// A response for a transaction index.
	TransactionIndex(transaction_index::Response),
	/// A response for a block's receipts.
	Receipts(block_receipts::Response),
	/// A response for a block body.
	Body(block_body::Response),
	/// A response for a merkle proof of an account.
	Account(account::Response),
	/// A response for a merkle proof of contract storage.
	Storage(storage::Response),
	/// A response for contract code.
	Code(contract_code::Response),
	/// A response for proof of execution,
	Execution(execution::Response),
	/// A response for epoch change signal.
	Signal(epoch_signal::Response),
}

impl ResponseLike for Response {
	/// Fill reusable outputs by writing them into the function.
	fn fill_outputs<F>(&self, f: F) where F: FnMut(usize, Output) {
		match *self {
			Response::Headers(ref res) => res.fill_outputs(f),
			Response::HeaderProof(ref res) => res.fill_outputs(f),
			Response::TransactionIndex(ref res) => res.fill_outputs(f),
			Response::Receipts(ref res) => res.fill_outputs(f),
			Response::Body(ref res) => res.fill_outputs(f),
			Response::Account(ref res) => res.fill_outputs(f),
			Response::Storage(ref res) => res.fill_outputs(f),
			Response::Code(ref res) => res.fill_outputs(f),
			Response::Execution(ref res) => res.fill_outputs(f),
			Response::Signal(ref res) => res.fill_outputs(f),
		}
	}
}

impl Response {
	/// Inspect the kind of this response.
	pub fn kind(&self) -> Kind {
		match *self {
			Response::Headers(_) => Kind::Headers,
			Response::HeaderProof(_) => Kind::HeaderProof,
			Response::TransactionIndex(_) => Kind::TransactionIndex,
			Response::Receipts(_) => Kind::Receipts,
			Response::Body(_) => Kind::Body,
			Response::Account(_) => Kind::Account,
			Response::Storage(_) => Kind::Storage,
			Response::Code(_) => Kind::Code,
			Response::Execution(_) => Kind::Execution,
			Response::Signal(_) => Kind::Signal,
		}
	}
}

impl Decodable for Response {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		match rlp.val_at::<Kind>(0)? {
			Kind::Headers => Ok(Response::Headers(rlp.val_at(1)?)),
			Kind::HeaderProof => Ok(Response::HeaderProof(rlp.val_at(1)?)),
			Kind::TransactionIndex => Ok(Response::TransactionIndex(rlp.val_at(1)?)),
			Kind::Receipts => Ok(Response::Receipts(rlp.val_at(1)?)),
			Kind::Body => Ok(Response::Body(rlp.val_at(1)?)),
			Kind::Account => Ok(Response::Account(rlp.val_at(1)?)),
			Kind::Storage => Ok(Response::Storage(rlp.val_at(1)?)),
			Kind::Code => Ok(Response::Code(rlp.val_at(1)?)),
			Kind::Execution => Ok(Response::Execution(rlp.val_at(1)?)),
			Kind::Signal => Ok(Response::Signal(rlp.val_at(1)?)),
		}
	}
}

impl Encodable for Response {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2);

		// hack around https://github.com/paritytech/parity-ethereum/issues/4356
		Encodable::rlp_append(&self.kind(), s);

		match *self {
			Response::Headers(ref res) => s.append(res),
			Response::HeaderProof(ref res) => s.append(res),
			Response::TransactionIndex(ref res) => s.append(res),
			Response::Receipts(ref res) => s.append(res),
			Response::Body(ref res) => s.append(res),
			Response::Account(ref res) => s.append(res),
			Response::Storage(ref res) => s.append(res),
			Response::Code(ref res) => s.append(res),
			Response::Execution(ref res) => s.append(res),
			Response::Signal(ref res) => s.append(res),
		};
	}
}

/// A potentially incomplete request.
pub trait IncompleteRequest: Sized {
	/// The complete variant of this request.
	type Complete;
	/// The response to this request.
	type Response: ResponseLike;

	/// Check prior outputs against the needed inputs.
	///
	/// This is called to ensure consistency of this request with
	/// others in the same packet.
	fn check_outputs<F>(&self, f: F) -> Result<(), NoSuchOutput>
		where F: FnMut(usize, usize, OutputKind) -> Result<(), NoSuchOutput>;

	/// Note that this request will produce the following outputs.
	fn note_outputs<F>(&self, f: F) where F: FnMut(usize, OutputKind);

	/// Fill fields of the request.
	///
	/// This function is provided an "output oracle" which allows fetching of
	/// prior request outputs.
	/// Only outputs previously checked with `check_outputs` may be available.
	fn fill<F>(&mut self, oracle: F) where F: Fn(usize, usize) -> Result<Output, NoSuchOutput>;

	/// Attempt to convert this request into its complete variant.
	/// Will succeed if all fields have been filled, will fail otherwise.
	fn complete(self) -> Result<Self::Complete, NoSuchOutput>;

	/// Adjust back-reference request indices.
	fn adjust_refs<F>(&mut self, mapping: F) where F: FnMut(usize) -> usize;
}

/// A request which can be checked against its response for more validity.
pub trait CheckedRequest: IncompleteRequest {
	/// Data extracted during the check.
	type Extract;
	/// Error encountered during the check.
	type Error;
	/// Environment passed to response check.
	type Environment;

	/// Check whether the response matches (beyond the type).
	fn check_response(&self, &Self::Complete, &Self::Environment, &Self::Response) -> Result<Self::Extract, Self::Error>;
}

/// A response-like object.
///
/// These contain re-usable outputs.
pub trait ResponseLike {
	/// Write all re-usable outputs into the provided function.
	fn fill_outputs<F>(&self, output_store: F) where F: FnMut(usize, Output);
}

#[cfg(test)]
mod tests {
	use super::*;
	use common_types::header::Header;

	fn check_roundtrip<T>(val: T)
		where T: ::rlp::Encodable + ::rlp::Decodable + PartialEq + ::std::fmt::Debug
	{
		// check as single value.
		let bytes = ::rlp::encode(&val);
		let new_val: T = ::rlp::decode(&bytes).unwrap();
		assert_eq!(val, new_val);

		// check as list containing single value.
		let list = [val];
		let bytes = ::rlp::encode_list(&list);
		let new_list: Vec<T> = ::rlp::decode_list(&bytes);
		assert_eq!(&list, &new_list[..]);
	}

	#[test]
	fn hash_or_number_roundtrip() {
		let hash = HashOrNumber::Hash(H256::default());
		let number = HashOrNumber::Number(5);

		check_roundtrip(hash);
		check_roundtrip(number);
	}

	#[test]
	fn field_roundtrip() {
		let field_scalar = Field::Scalar(5usize);
		let field_back: Field<usize> = Field::BackReference(1, 2);

		check_roundtrip(field_scalar);
		check_roundtrip(field_back);
	}

	#[test]
	fn headers_roundtrip() {
		let req = header::IncompleteRequest {
			start: Field::Scalar(5u64.into()),
			skip: 0,
			max: 100,
			reverse: false,
		};

		let full_req = Request::Headers(req.clone());
		let res = header::Response {
			headers: vec![
				::common_types::encoded::Header::new(::rlp::encode(&Header::default()))
			]
		};
		let full_res = Response::Headers(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn header_proof_roundtrip() {
		let req = header_proof::IncompleteRequest {
			num: Field::BackReference(1, 234),
		};

		let full_req = Request::HeaderProof(req.clone());
		let res = header_proof::Response {
			proof: vec![vec![1, 2, 3], vec![4, 5, 6]],
			hash: Default::default(),
			td: 100.into(),
		};
		let full_res = Response::HeaderProof(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn transaction_index_roundtrip() {
		let req = transaction_index::IncompleteRequest {
			hash: Field::Scalar(Default::default()),
		};

		let full_req = Request::TransactionIndex(req.clone());
		let res = transaction_index::Response {
			num: 1000,
			hash: ::ethereum_types::H256::random(),
			index: 4,
		};
		let full_res = Response::TransactionIndex(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn receipts_roundtrip() {
		use common_types::receipt::{Receipt, TransactionOutcome};
		let req = block_receipts::IncompleteRequest {
			hash: Field::Scalar(Default::default()),
		};

		let full_req = Request::Receipts(req.clone());
		let receipt = Receipt::new(TransactionOutcome::Unknown, Default::default(), Vec::new());
		let res = block_receipts::Response {
			receipts: vec![receipt.clone(), receipt],
		};
		let full_res = Response::Receipts(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn body_roundtrip() {
		use common_types::transaction::{Transaction, UnverifiedTransaction};
		let req = block_body::IncompleteRequest {
			hash: Field::Scalar(Default::default()),
		};

		let full_req = Request::Body(req.clone());
		let res = block_body::Response {
			body: {
				let header = ::common_types::header::Header::default();
				let tx = UnverifiedTransaction::from(Transaction::default().fake_sign(Default::default()));
				let mut stream = RlpStream::new_list(2);
				stream.begin_list(2).append(&tx).append(&tx)
					.begin_list(1).append(&header);

				::common_types::encoded::Body::new(stream.out())
			},
		};
		let full_res = Response::Body(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn account_roundtrip() {
		let req = account::IncompleteRequest {
			block_hash: Field::Scalar(Default::default()),
			address_hash: Field::BackReference(1, 2),
		};

		let full_req = Request::Account(req.clone());
		let res = account::Response {
			proof: vec![vec![1, 2, 3], vec![4, 5, 6]],
			nonce: 100.into(),
			balance: 123456.into(),
			code_hash: Default::default(),
			storage_root: Default::default(),
		};
		let full_res = Response::Account(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn storage_roundtrip() {
		let req = storage::IncompleteRequest {
			block_hash: Field::Scalar(Default::default()),
			address_hash: Field::BackReference(1, 2),
			key_hash: Field::BackReference(3, 2),
		};

		let full_req = Request::Storage(req.clone());
		let res = storage::Response {
			proof: vec![vec![1, 2, 3], vec![4, 5, 6]],
			value: H256::default(),
		};
		let full_res = Response::Storage(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn code_roundtrip() {
		let req = contract_code::IncompleteRequest {
			block_hash: Field::Scalar(Default::default()),
			code_hash: Field::BackReference(3, 2),
		};

		let full_req = Request::Code(req.clone());
		let res = contract_code::Response {
			code: vec![1, 2, 3, 4, 5, 6, 7, 6, 5, 4],
		};
		let full_res = Response::Code(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn execution_roundtrip() {
		use kvdb::DBValue;

		let req = execution::IncompleteRequest {
			block_hash: Field::Scalar(Default::default()),
			from: Default::default(),
			action: ::common_types::transaction::Action::Create,
			gas: 100_000.into(),
			gas_price: 0.into(),
			value: 100_000_001.into(),
			data: vec![1, 2, 3, 2, 1],
		};

		let full_req = Request::Execution(req.clone());
		let res = execution::Response {
			items: vec![DBValue::new(), {
				let mut value = DBValue::new();
				value.append_slice(&[1, 1, 1, 2, 3]);
				value
			}],
		};
		let full_res = Response::Execution(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}

	#[test]
	fn vec_test() {
		use rlp::*;

		let reqs: Vec<_> = (0..10).map(|_| execution::IncompleteRequest {
			block_hash: Field::Scalar(Default::default()),
			from: Default::default(),
			action: ::common_types::transaction::Action::Create,
			gas: 100_000.into(),
			gas_price: 0.into(),
			value: 100_000_001.into(),
			data: vec![1, 2, 3, 2, 1],
		}).map(Request::Execution).collect();

		let mut stream = RlpStream::new_list(2);
		stream.append(&100usize).append_list(&reqs);
		let out = stream.out();

		let rlp = Rlp::new(&out);
		assert_eq!(rlp.val_at::<usize>(0).unwrap(), 100usize);
		assert_eq!(rlp.list_at::<Request>(1).unwrap(), reqs);
	}

	#[test]
	fn responses_vec() {
		use common_types::receipt::{Receipt, TransactionOutcome};
		let mut stream = RlpStream::new_list(2);
				stream.begin_list(0).begin_list(0);

		let body = ::common_types::encoded::Body::new(stream.out());
		let reqs = vec![
			Response::Headers(header::Response { headers: vec![] }),
			Response::HeaderProof(header_proof::Response { proof: vec![], hash: Default::default(), td: 100.into()}),
			Response::Receipts(block_receipts::Response { receipts: vec![Receipt::new(TransactionOutcome::Unknown, Default::default(), Vec::new())] }),
			Response::Body(block_body::Response { body: body }),
			Response::Account(account::Response {
				proof: vec![],
				nonce: 100.into(),
				balance: 123.into(),
				code_hash: Default::default(),
				storage_root: Default::default()
			}),
			Response::Storage(storage::Response { proof: vec![], value: H256::default() }),
			Response::Code(contract_code::Response { code: vec![1, 2, 3, 4, 5] }),
			Response::Execution(execution::Response { items: vec![] }),
		];

		let raw = ::rlp::encode_list(&reqs);
		assert_eq!(::rlp::decode_list::<Response>(&raw), reqs);
	}

	#[test]
	fn epoch_signal_roundtrip() {
		let req = epoch_signal::IncompleteRequest {
			block_hash: Field::Scalar(Default::default()),
		};

		let full_req = Request::Signal(req.clone());
		let res = epoch_signal::Response {
			signal: vec![1, 2, 3, 4, 5, 6, 7, 6, 5, 4],
		};
		let full_res = Response::Signal(res.clone());

		check_roundtrip(req);
		check_roundtrip(full_req);
		check_roundtrip(res);
		check_roundtrip(full_res);
	}
}
