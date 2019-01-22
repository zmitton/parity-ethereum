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

use std::collections::HashMap;
use std::io::{self, Read};
use std::{path, fs};

use ethjson::uint::Uint;
use ethjson::hash::{Address, H256};
use ethjson::bytes::Bytes;

use serde::{Deserialize, Deserializer};
use serde_json;


#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixture {
        #[serde(skip)]
        pub name: String,
        #[serde(rename = "_info")]
        pub info: Info,
        pub env: Env,
        pub pre: HashMap<Address, PreState>,
        pub post: HashMap<CodeName, Vec<PostState>>,
        pub transaction: Transaction
}


#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreState {
        pub balance: Uint,
        #[serde(deserialize_with = "maybe_bytes")]
        pub code: Option<Bytes>,
        pub nonce: Uint,
        pub storage: HashMap<String, String>
}

#[derive(Debug, Eq, PartialEq, Hash, Deserialize)]
pub enum CodeName {
        Byzantium
}

#[derive(Debug, Deserialize)]
pub struct PostState {
        pub hash: H256,
        pub indexes: Indexes,
        pub logs: H256
}

#[derive(Debug, Deserialize)]
pub struct Indexes {
        pub data: Uint,
        pub gas: Uint,
        pub value: Uint
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Info {
        pub comment: String,
        #[serde(rename = "filledwith")]
        pub filled_with: String,
        #[serde(rename = "lllcversion")]
        pub lllc_version: String,
        pub source: String,
        pub source_hash: String
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Env {
        pub current_coinbase: Address,
        pub current_difficulty: Uint,
        pub current_gas_limit: Uint,
        pub current_number: Uint,
        pub current_timestamp: Uint,
        pub previous_hash: H256
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
        pub data: Vec<Bytes>,
        pub gas_limit: Vec<Uint>,
        pub gas_price: Uint,
        pub nonce: Uint,
        pub secret_key: H256,
        pub to: Address,
        pub value: Vec<Uint>
}


fn file_contents(filename: &path::Path) -> Result<Vec<u8>, io::Error> {
        let mut bytes = Vec::new();
        fs::File::open(filename)?.read_to_end(&mut bytes)?;
        Ok(bytes)
}

fn maybe_bytes<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
        where D: Deserializer<'de>
{
        let bytes = Bytes::deserialize(deserializer)?;
        if bytes.len() == 0 {
                Ok(None)
        } else {
                Ok(Some(bytes))
        }
}

pub fn deserialize(filename: &str) -> Result<Fixture, io::Error> {
        let path = path::Path::new(filename);
        let bytes = file_contents(&path)?;
        let name = path.file_stem().expect("file stem").to_str().expect("converted top key");
        let top_obj: serde_json::Value = serde_json::from_slice(&bytes)?;
        let content_obj = top_obj.get(&name).expect(&format!("top level key {}", name));
        let mut fixture: Fixture = serde_json::from_value(content_obj.clone())?;
        fixture.name = name.to_owned();
        Ok(fixture)
}
