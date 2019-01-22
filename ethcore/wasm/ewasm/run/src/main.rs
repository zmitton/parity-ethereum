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

extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate ethereum_types;
extern crate ethjson;
extern crate wasm;
extern crate vm;
extern crate clap;
// extern crate ethcore_logger;
extern crate rustc_hex;
extern crate keccak_hash as hash;

mod fixture;
mod runner;

use clap::{App, Arg};

fn main() {
//	ethcore_logger::init_log();

	let matches = App::new("ewasm-run-test")
		.arg(Arg::with_name("target")
		     .index(1)
		     .required(true)
		     .multiple(true)
		     .help("JSON fixture"))
		.get_matches();

	//let mut exit_code = 0;

	for target in matches.values_of("target").expect("target parameter") {

                let fixture = fixture::deserialize(&target).expect("deserialized fixture");
                // println!("{:#?}", fixture);

                runner::run_fixture(fixture);

	}

	std::process::exit(1);
}
