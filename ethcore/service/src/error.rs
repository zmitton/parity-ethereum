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

use std::error;
use ethcore;
use derive_more::{Display, From};
use io;
use ethcore_private_tx;

#[derive(Debug, Display, From)]
pub enum Error {
	/// Ethcore error
	#[display(fmt = "Ethcore error: {}", _0)]
	Ethcore(ethcore::error::Error),
	/// Io error
	#[display(fmt = "Io error {}", _0)]
	IoError(io::IoError),
	/// Private transactions error
	#[display(fmt = "Private transactions error {}", _0)]
	PrivateTransactions(ethcore_private_tx::Error),
}

impl error::Error for Error {
	fn source(&self) -> Option<&(error::Error + 'static)> {
		match self {
			Error::Ethcore(e) => Some(e),
			Error::IoError(e) => Some(e),
			Error::PrivateTransactions(e) => Some(e),
		}
	}
}
