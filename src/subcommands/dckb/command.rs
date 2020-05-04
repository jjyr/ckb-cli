use crate::subcommands::dckb::util::{
    calculate_dao_maximum_withdraw, calculate_dao_maximum_withdraw_with_header, send_transaction,
};
use crate::subcommands::{CliSubCommand, DCKBSubCommand};
use crate::utils::{
    arg,
    arg_parser::{
        AddressParser, ArgParser, CapacityParser, FixedHashParser, OutPointParser,
        PrivkeyPathParser, PrivkeyWrapper,
    },
    other::{get_address, get_network_type},
    printer::{OutputFormat, Printable},
};
use ckb_crypto::secp::SECP256K1;
use ckb_sdk::{constants::SIGHASH_TYPE_HASH, Address, AddressPayload, NetworkType};
use ckb_types::{
    core::HeaderView,
    packed::{Byte32, Script},
    prelude::*,
    H160, H256,
};
use clap::{App, Arg, ArgMatches, SubCommand};
use std::collections::HashSet;

impl<'a> CliSubCommand for DCKBSubCommand<'a> {
    fn process(
        &mut self,
        matches: &ArgMatches,
        format: OutputFormat,
        color: bool,
        debug: bool,
    ) -> Result<String, String> {
        let network_type = get_network_type(&mut self.rpc_client)?;
        match matches.subcommand() {
            ("deposit", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
                let transaction = self.deposit(capacity)?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("transfer", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let capacity: u64 = CapacityParser.from_matches(m, "capacity")?;
                let mut address_parser = AddressParser::default();
                address_parser.set_network(network_type);
                let target_address: Address = address_parser.from_matches(m, "to-address")?;
                let target_lock = Script::from(target_address.payload());
                let transaction = self.transfer(capacity, target_lock)?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("prepare", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self.prepare(out_points)?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("withdraw", Some(m)) => {
                self.transact_args = Some(TransactArgs::from_matches(m, network_type)?);
                let out_points = OutPointParser.from_matches_vec(m, "out-point")?;
                if out_points.len() != out_points.iter().collect::<HashSet<_>>().len() {
                    return Err("Duplicated out-points".to_string());
                }
                let transaction = self.withdraw(out_points)?;
                send_transaction(self.rpc_client(), transaction, format, color, debug)
            }
            ("query-dckb", Some(m)) => {
                let query_args = QueryArgs::from_matches(m, network_type)?;
                let lock_hash = query_args.lock_hash;
                let (cells, tip) = self.query_dckb_cells(lock_hash)?;
                let total_capacity = cells.iter().map(|live| live.cell.capacity).sum::<u64>();
                let total_dckb = cells.iter().map(|live| live.dckb_amount).sum::<u64>();
                let tip_number: u64 = tip.data().raw().number().unpack();
                let resp = serde_json::json!({
                    "dckb_cells": cells.into_iter().map(|info| {
                        serde_json::to_value(&info).unwrap()
                    }).collect::<Vec<_>>(),
                    "total_capacity": total_capacity,
                    "total_dckb": total_dckb,
                    "tip_number": tip_number,
                });
                Ok(resp.render(format, color))
            }
            ("query-dao-cells", Some(m)) => {
                let query_args = QueryArgs::from_matches(m, network_type)?;
                let lock_hash = query_args.lock_hash;
                let cells = self.query_dao_cells(lock_hash)?;
                let total_capacity = cells.iter().map(|live| live.capacity).sum::<u64>();
                // let maximum_withdraws: Vec<_> = cells
                //     .iter()
                //     .map(|cell| calculate_dao_maximum_withdraw(self.rpc_client(), cell))
                //     .collect::<Result<Vec<u64>, String>>()?;
                let tip: HeaderView = self.rpc_client.get_tip_header()?.into();
                let maximum_withdraws: Vec<_> = cells
                    .iter()
                    .map(|cell| {
                        calculate_dao_maximum_withdraw_with_header(self.rpc_client(), cell, &tip)
                    })
                    .collect::<Result<Vec<u64>, String>>()?;
                let total_maximum_withdraw = maximum_withdraws.iter().sum::<u64>();
                let resp = serde_json::json!({
                    "live_cells": (0..cells.len()).map(|i| {
                        let mut value = serde_json::to_value(&cells[i]).unwrap();
                        let obj = value.as_object_mut().unwrap();
                        obj.insert("maximum_withdraw".to_owned(), serde_json::json!(maximum_withdraws[i]));
                        value
                    }).collect::<Vec<_>>(),
                    "total_maximum_withdraw": total_maximum_withdraw,
                    "total_capacity": total_capacity,
                });
                Ok(resp.render(format, color))
            }
            ("query-prepared-cells", Some(m)) => {
                let query_args = QueryArgs::from_matches(m, network_type)?;
                let lock_hash = query_args.lock_hash;
                let cells = self.query_prepare_cells(lock_hash)?;
                let maximum_withdraws: Vec<_> = cells
                    .iter()
                    .map(|cell| calculate_dao_maximum_withdraw(self.rpc_client(), cell))
                    .collect::<Result<Vec<u64>, String>>()?;
                let total_maximum_withdraw = maximum_withdraws.iter().sum::<u64>();
                let resp = serde_json::json!({
                    "live_cells": (0..cells.len()).map(|i| {
                        let mut value = serde_json::to_value(&cells[i]).unwrap();
                        let obj = value.as_object_mut().unwrap();
                        obj.insert("maximum_withdraw".to_owned(), serde_json::json!(maximum_withdraws[i]));
                        value
                    }).collect::<Vec<_>>(),
                    "total_maximum_withdraw": total_maximum_withdraw,
                });
                Ok(resp.render(format, color))
            }
            _ => Err(matches.usage().to_owned()),
        }
    }
}

impl<'a> DCKBSubCommand<'a> {
    pub fn subcommand() -> App<'static, 'static> {
        SubCommand::with_name("dckb")
            .about("Deposit / prepare / withdraw / query DCKB balance (with local index) / key utils")
            .subcommands(vec![
                SubCommand::with_name("deposit")
                    .about("Deposit capacity into NervosDAO")
                    .args(&TransactArgs::args())
                    .arg(arg::capacity().required(true)),
                SubCommand::with_name("transfer")
                    .about("transfer dckb")
                    .args(&TransactArgs::args())
                    .arg(arg::capacity().required(true))
                    .arg(arg::to_address().required(true)),
                SubCommand::with_name("prepare")
                    .about("Perform phase 1 withdraw from NervosDAO (destroy deposited amount DCKB), WARN: make sure you can perform phase2 withdraw within 42 epochs(~ 7 days), otherwise your coin will lose")
                    .args(&TransactArgs::args())
                    .arg(arg::out_point().required(true).multiple(true)),
                SubCommand::with_name("withdraw")
                    .about("Perform phase 2 withdraw from NervosDAO (destroy compensation DCKB)")
                    .args(&TransactArgs::args())
                    .arg(arg::out_point().required(true).multiple(true)),
                SubCommand::with_name("query-dckb")
                    .about("Query DCKB amount by lock script hash or address")
                    .args(&QueryArgs::args()),
                SubCommand::with_name("query-dao-cells")
                    .about("Query deposited dao cells")
                    .args(&QueryArgs::args()),
                SubCommand::with_name("query-prepared-cells")
                    .about("Query phase1 withdraw cells by lock script hash or address")
                    .args(&QueryArgs::args())
            ])
    }
}

pub(crate) struct QueryArgs {
    pub(crate) lock_hash: Byte32,
}

pub(crate) struct TransactArgs {
    pub(crate) privkey: Option<PrivkeyWrapper>,
    pub(crate) address: Address,
    pub(crate) tx_fee: u64,
}

impl QueryArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let lock_hash_opt: Option<H256> =
            FixedHashParser::<H256>::default().from_matches_opt(m, "lock-hash", false)?;
        let lock_hash = if let Some(lock_hash) = lock_hash_opt {
            lock_hash.pack()
        } else {
            let address = get_address(Some(network_type), m)?;
            Script::from(&address).calc_script_hash()
        };

        Ok(Self { lock_hash })
    }

    fn args<'a, 'b>() -> Vec<Arg<'a, 'b>> {
        vec![arg::lock_hash(), arg::address()]
    }
}

impl TransactArgs {
    fn from_matches(m: &ArgMatches, network_type: NetworkType) -> Result<Self, String> {
        let privkey: Option<PrivkeyWrapper> =
            PrivkeyPathParser.from_matches_opt(m, "privkey-path", false)?;
        let address = if let Some(privkey) = privkey.as_ref() {
            let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, privkey);
            let payload = AddressPayload::from_pubkey(&pubkey);
            Address::new(network_type, payload)
        } else {
            let account: Option<H160> = FixedHashParser::<H160>::default()
                .from_matches_opt(m, "from-account", false)
                .or_else(|err| {
                    let result: Result<Option<Address>, String> = AddressParser::new_sighash()
                        .set_network(network_type)
                        .from_matches_opt(m, "from-account", false);
                    result
                        .map(|address_opt| {
                            address_opt
                                .map(|address| H160::from_slice(&address.payload().args()).unwrap())
                        })
                        .map_err(|_| format!("Invalid value for '--from-account': {}", err))
                })?;
            let payload = AddressPayload::from_pubkey_hash(account.unwrap());
            Address::new(network_type, payload)
        };
        assert_eq!(address.payload().code_hash(), SIGHASH_TYPE_HASH.pack());
        let tx_fee: u64 = CapacityParser.from_matches(m, "tx-fee")?;
        Ok(Self {
            privkey,
            address,
            tx_fee,
        })
    }

    fn args<'a, 'b>() -> Vec<Arg<'a, 'b>> {
        vec![
            arg::privkey_path().required_unless(arg::from_account().b.name),
            arg::from_account().required_unless(arg::privkey_path().b.name),
            arg::tx_fee().required(true),
        ]
    }

    pub(crate) fn sighash_args(&self) -> H160 {
        H160::from_slice(self.address.payload().args().as_ref()).unwrap()
    }

    pub(crate) fn lock_script(&self) -> Script {
        Script::from(self.address.payload())
    }

    pub(crate) fn lock_hash(&self) -> Byte32 {
        Script::from(self.address.payload()).calc_script_hash()
    }
}
