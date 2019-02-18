//! Header request.

use super::{Field, HashOrNumber, NoSuchOutput, OutputKind, Output};
use common_types::encoded;
use rlp::{Encodable, Decodable, DecoderError, RlpStream, Rlp};

/// Potentially incomplete headers request.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct IncompleteHeadersRequest {
	/// Start block.
	pub start: Field<HashOrNumber>,
	/// Skip between.
	pub skip: u64,
	/// Maximum to return.
	pub max: u64,
	/// Whether to reverse from start.
	pub reverse: bool,
}

impl super::IncompleteRequest for IncompleteHeadersRequest {
	type Complete = CompleteHeadersRequest;
	type Response = HeadersResponse;

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
		Ok(CompleteHeadersRequest {
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
pub struct CompleteHeadersRequest {
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
pub struct HeadersResponse {
	/// The headers requested.
	pub headers: Vec<encoded::Header>,
}

impl super::ResponseLike for HeadersResponse {
	/// Fill reusable outputs by writing them into the function.
	fn fill_outputs<F>(&self, _: F) where F: FnMut(usize, Output) { }
}

impl Decodable for HeadersResponse {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		use common_types::header::Header as FullHeader;

		let mut headers = Vec::new();

		for item in rlp.iter() {
			// check that it's a valid encoding.
			// TODO: just return full headers here?
			let _: FullHeader = item.as_val()?;
			headers.push(encoded::Header::new(item.as_raw().to_owned()));
		}

		Ok(HeadersResponse { headers })
	}
}

impl Encodable for HeadersResponse {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(self.headers.len());
		for header in &self.headers {
			s.append_raw(header.rlp().as_raw(), 1);
		}
	}
}
