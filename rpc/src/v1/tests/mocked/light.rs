use ethcore::account_provider::AccountProvider;
use ethcore::spec::Spec;
use jsonrpc_core::IoHandler;
use io::IoChannel;
use light::client::fetch::{self, Unavailable};
use light::cache::Cache;
use light::net::LightProtocol;
use light::on_demand::OnDemand;
use light::provider::LightProvider;
use network::NetworkConfiguration as BasicNetworkConfiguration;
use sync::{LightSync, LightSyncParams, ManageNetwork};
use parking_lot::{Mutex, RwLock};
use parity_runtime::Runtime;
use v1::light::EthClient as LightEthClient;
use v1::metadata::Metadata;
use v1::traits::eth::Eth;

use std::time::Duration;
use std::sync::Arc;

type LightClient = light::client::Client<Unavailable>;

fn accounts_provider() -> Arc<AccountProvider> {
	Arc::new(AccountProvider::transient_provider())
}

fn light_client(cache: Arc<Mutex<Cache>>) -> Arc<LightClient> {
	let mut config = ::light::client::Config::default();
	// skip full verification because the blocks are bad.
	config.verify_full = false;
	let db = kvdb_memorydb::create(0);
	Arc::new(LightClient::new(
		config,
		Arc::new(db),
		None,
		&Spec::new_test(),
		fetch::unavailable(), // TODO: allow fetch from full nodes.
		IoChannel::disconnected(),
		cache,
	).expect("New DB creation infallible; qed"))
}

// FIXME: check if `no_immediate dispatch` is needed
fn on_demand(cache: Arc<Mutex<Cache>>) -> Arc<OnDemand> {
	Arc::new(OnDemand::new(
		cache,
		Duration::from_secs(60),
		Duration::from_secs(30),
		Duration::from_secs(60),
		10,
		2,
	))
}

struct EthTester {
	pub runtime: Runtime,
	pub client: Arc<light::client::Client<Unavailable>>,
	pub sync: Arc<LightSync>,
	pub accounts_provider: Arc<AccountProvider>,
	pub io: IoHandler<Metadata>,
}

impl EthTester {
	pub fn default() -> Self {
		let runtime = Runtime::with_thread_count(1);
		let accounts_provider = accounts_provider();
		let cache = Arc::new(Mutex::new(Cache::new(Default::default(), Duration::from_secs(6 * 3600))));
		let on_demand = on_demand(cache.clone());
		let client = light_client(cache.clone());

		let tx_queue = Arc::new(RwLock::new(light::transaction_queue::TransactionQueue::default()));
		let provider = Arc::new(LightProvider::new(client.clone(), tx_queue.clone()));

		let sync_params = LightSyncParams {
			network_config: BasicNetworkConfiguration::default(),
			client: provider.clone(),
			network_id: 0_u64,
			subprotocol_name: sync::LIGHT_PROTOCOL,
			handlers: vec![on_demand.clone()],
			attached_protos: Vec::new(),
		};

		let sync = Arc::new(LightSync::new(sync_params).unwrap());
		sync.start_network();

		let eth = LightEthClient::new(sync.clone(), client.clone(), on_demand, tx_queue, accounts_provider.clone(),
									  cache.clone(), 0, 0).to_delegate();
		let mut io: IoHandler<Metadata> = IoHandler::default();
		io.extend_with(eth);

		EthTester {
			runtime,
			client,
			sync,
			accounts_provider,
			io,
		}
	}
}


#[test]
fn light() {
	let request = r#"{
		"jsonrpc": "2.0",
		"method": "eth_estimateGas",
		"params": [{
			"from": "0xb60e8dd61c5d32be8058bb8eb970870f07233155",
			"to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
			"gas": "0x76c0",
			"gasPrice": "0x9184e72a000",
			"value": "0x9184e72a",
			"data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
		},
		"latest"],
		"id": 1
	}"#;
	let tester = EthTester::default();
	assert_eq!(tester.io.handle_request_sync(request), Some("".to_owned()));
}
