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

use std::path::Path;
use ethcore_db::NUM_COLUMNS;
use ethcore::client::{DatabaseCompactionProfile, DatabaseBackend};
use super::kvdb_rocksdb::{CompactionProfile, DatabaseConfig};
use super::KvdbBackend;

pub fn compaction_profile(profile: &DatabaseCompactionProfile, db_path: &Path) -> CompactionProfile {
	match profile {
		&DatabaseCompactionProfile::Auto => CompactionProfile::auto(db_path),
		&DatabaseCompactionProfile::SSD => CompactionProfile::ssd(),
		&DatabaseCompactionProfile::HDD => CompactionProfile::hdd(),
	}
}

pub fn client_db_config(client_path: &Path, db_backend: &DatabaseBackend) -> KvdbBackend {
	match db_backend {
		DatabaseBackend::Lmdb => KvdbBackend::Lmdb,
		DatabaseBackend::RocksDB { ref db_cache_size, ref db_compaction } => {
			let mut config = DatabaseConfig::with_columns(NUM_COLUMNS);

			config.memory_budget = *db_cache_size;
			config.compaction = compaction_profile(db_compaction, &client_path);
 
			KvdbBackend::RocksDB { config }
		} 
	}
}
