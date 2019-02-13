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

extern crate kvdb_lmdb;
extern crate ethcore_blockchain;

use std::{io, fs};
use std::sync::Arc;
use std::path::Path;
use blooms_db;
use ethcore_db::NUM_COLUMNS;
use kvdb::KeyValueDB;
use self::ethcore_blockchain::{BlockChainDBHandler, BlockChainDB};
use self::kvdb_lmdb::Database as Lmdb;

mod blooms;


/// Migrates the database.
pub fn migrate(path: &Path) -> Result<(), String> {
	debug!(target: "lmdb", "migration isn't implemented yet");
	Ok(())
}

struct AppDB {
	key_value: Arc<KeyValueDB>,
	blooms: blooms_db::Database,
	trace_blooms: blooms_db::Database,
}

impl BlockChainDB for AppDB {
	fn key_value(&self) -> &Arc<KeyValueDB> {
		&self.key_value
	}

	fn blooms(&self) -> &blooms_db::Database {
		&self.blooms
	}

	fn trace_blooms(&self) -> &blooms_db::Database {
		&self.trace_blooms
	}
}

/// Open a secret store DB using the given secret store data path. The DB path is one level beneath the data path.
#[cfg(feature = "secretstore")]
pub fn open_secretstore_db(data_path: &str) -> Result<Arc<KeyValueDB>, String> {
	use std::path::PathBuf;

	let mut db_path = PathBuf::from(data_path);
	db_path.push("db");
	let db_path = db_path.to_str().ok_or_else(|| "Invalid secretstore path".to_string())?;
	open_kvdb(&db_path).map_err(|e| format!("Error opening database: {:?}", e))
}

/// Create a restoration db handler.
pub fn restoration_db_handler() -> Box<BlockChainDBHandler> {
	struct RestorationDBHandler {}

	impl BlockChainDBHandler for RestorationDBHandler {
		fn open(&self, db_path: &Path) -> io::Result<Arc<BlockChainDB>> {
			open_db(&db_path.to_string_lossy())
		}
	}

	Box::new(RestorationDBHandler {})
}

/// Open a new main DB.
pub fn open_db(client_path: &str) -> io::Result<Arc<BlockChainDB>> {
	let path = Path::new(client_path);

	let blooms_path = path.join("blooms");
	let trace_blooms_path = path.join("trace_blooms");
	fs::create_dir_all(&blooms_path)?;
	fs::create_dir_all(&trace_blooms_path)?;

	let db = AppDB {
		key_value: open_kvdb(client_path)?,
		blooms: blooms_db::Database::open(blooms_path)?,
		trace_blooms: blooms_db::Database::open(trace_blooms_path)?,
	};

	Ok(Arc::new(db))
}



fn open_kvdb(client_path: &str) -> io::Result<Arc<KeyValueDB>> {
	Ok(Arc::new(Lmdb::open(client_path, NUM_COLUMNS.unwrap_or_default())?))
}