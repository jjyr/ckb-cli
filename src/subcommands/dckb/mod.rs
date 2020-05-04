use self::builder::{dckb_script, DAOBuilder};
use self::command::TransactArgs;
use self::util::{calculate_dao_capacity, calculate_dao_maximum_withdraw, load_dckb_data};
use crate::utils::index::IndexController;
use crate::utils::other::{
    get_max_mature_number, get_network_type, get_privkey_signer, is_mature, read_password,
    serialize_signature,
};
use byteorder::{ByteOrder, LittleEndian};
use ckb_hash::new_blake2b;
use ckb_index::{with_index_db, CellIndex, IndexDatabase, LiveCellInfo};
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{
    constants::MIN_SECP_CELL_CAPACITY, wallet::KeyStore, GenesisInfo, HttpRpcClient, NetworkType,
    SignerFn,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, HeaderView, ScriptHashType, TransactionView},
    packed::{Byte32, CellDep, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    {h256, H160, H256},
};
use environment::DCKBENV;
use itertools::Itertools;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

mod builder;
mod command;
mod environment;
mod util;

const DCKB_CAPACITY: u64 = 118_00000000;
const DCKB_DAO_CELL_CAPACITY: u64 = 146_00000000;
const SECP256K1_CAPACITY: u64 = 61_00000000;
const CUSTODIAN_CELL_CAPACITY: u64 = 130_00000000;

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct DCKBLiveCellInfo {
    dckb_amount: u64,
    dckb_height: u64,
    cell: LiveCellInfo,
}

pub struct DCKBSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    key_store: &'a mut KeyStore,
    genesis_info: GenesisInfo,
    index_dir: PathBuf,
    index_controller: IndexController,
    transact_args: Option<TransactArgs>,
    dckb_env: DCKBENV,
}

impl<'a> DCKBSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        key_store: &'a mut KeyStore,
        genesis_info: GenesisInfo,
        index_dir: PathBuf,
        index_controller: IndexController,
    ) -> Self {
        let network = get_network_type(rpc_client).unwrap_or(NetworkType::Dev);
        let dckb_env = DCKBENV::from_network(network);
        Self {
            rpc_client,
            key_store,
            genesis_info,
            dckb_env,
            index_dir,
            index_controller,
            transact_args: None,
        }
    }

    pub fn deposit(&mut self, capacity: u64) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let target_capacity = capacity + self.transact_args().tx_fee;
        let cells = self.collect_sighash_cells(target_capacity)?;
        let tx = self.build(cells).deposit(capacity)?;
        let tx = self.install_dao_lock(tx, &[0]);
        let output_len = tx.outputs().len();
        let tx = self.install_sighash_lock(tx, &(1..output_len).collect::<Vec<_>>());
        let len = tx.witnesses().len();
        let tx = self.sign(tx, 0, len)?;
        Ok(tx)
    }

    pub fn transfer(
        &mut self,
        dckb_amount: u64,
        target_lock: Script,
    ) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let tx_fee = self.transact_args().tx_fee;
        // fee + 1 CKB withdraw cell + 2 DCKB withdraw cells
        let target_capacity = tx_fee + Capacity::bytes(61).unwrap().as_u64() + 2 * DCKB_CAPACITY;
        let live_cells = self.collect_sighash_cells(target_capacity)?;
        let tip: HeaderView = self.rpc_client().get_tip_header()?.into();
        let cells = self.collect_dckb_live_cells(dckb_amount, &tip)?;
        let tx = self.build(live_cells).transfer(
            self.rpc_client(),
            cells,
            tip,
            dckb_amount,
            target_capacity,
            target_lock,
        )?;
        let output_len = tx.outputs().len();
        let tx = self.install_sighash_lock(tx, &(1..output_len).collect::<Vec<_>>());
        let len = tx.witnesses().len();
        let tx = self.sign(tx, 0, len)?;
        Ok(tx)
    }

    pub fn prepare(&mut self, out_points: Vec<OutPoint>) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let tx_fee = self.transact_args().tx_fee;
        let lock_hash = self.transact_args().lock_hash();
        let mut cells = {
            let deposit_cells = self.query_dao_cells(lock_hash.clone())?;
            take_by_out_points(deposit_cells, &out_points)?
        };
        // destroy dckb
        let target_capacity =
            cells.iter().map(|cell| cell.capacity).sum::<u64>() - DCKB_DAO_CELL_CAPACITY;
        // aapend fee cell
        let extra_capacity = tx_fee + DCKB_CAPACITY + CUSTODIAN_CELL_CAPACITY + SECP256K1_CAPACITY;
        let mut to_pay_fee = self.collect_sighash_cells(extra_capacity)?;
        cells.append(&mut to_pay_fee);
        let align_target: HeaderView = {
            let tip: HeaderView = self.rpc_client().get_tip_header()?.into();
            let epoch_number = tip.epoch().number() - 4;
            let target_epoch = self
                .rpc_client()
                .get_epoch_by_number(epoch_number)?
                .expect("epoch info");
            self.rpc_client()
                .get_header_by_number(target_epoch.start_number)?
                .expect("align target")
                .into()
        };
        let dckb_cells = self.collect_dckb_live_cells(target_capacity, &align_target)?;
        let tx = self
            .build(cells)
            .prepare(self.rpc_client(), dckb_cells, align_target)?;
        let output_len = tx.outputs().len();
        let tx = self.install_custodian_lock(tx, &[(output_len - 1) as usize]);
        let tx = self.install_sighash_lock(tx, &(1..(output_len - 1)).collect::<Vec<_>>());
        let len = tx.witnesses().len();
        self.sign(tx, 1, len)
    }

    pub fn withdraw(&mut self, out_points: Vec<OutPoint>) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let tx_fee = self.transact_args().tx_fee;
        let lock_hash = self.transact_args().lock_hash();
        let mut cells = {
            let deposit_cells = self.query_prepare_cells(lock_hash.clone())?;
            take_by_out_points(deposit_cells, &out_points)?
        };
        let (custodian_cell, prepare_header) = {
            let tx_hash = out_points[0].tx_hash();
            let tx = self
                .rpc_client()
                .get_transaction(tx_hash.unpack())?
                .expect("tx");
            let (index, _) = tx
                .transaction
                .inner
                .outputs
                .iter()
                .enumerate()
                .find(|(_i, output)| {
                    output.lock.code_hash == self.dckb_env.custodian_lock_code_hash.into()
                })
                .expect("find custodian cell");
            let data = tx.transaction.inner.outputs_data[index].as_bytes();
            let output = tx.transaction.inner.outputs[index].clone();
            debug_assert_eq!(data.len(), 24);
            let dckb_amount = {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&data[..16]);
                u128::from_le_bytes(buf) as u64
            };
            let dckb_height = {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[16..]);
                u64::from_le_bytes(buf)
            };
            let prepare_header: HeaderView = self
                .rpc_client()
                .get_header(tx.tx_status.block_hash.unwrap())?
                .expect("get prepare header")
                .into();
            // TODO query from ckb-cli?
            let cell = DCKBLiveCellInfo {
                dckb_height,
                dckb_amount,
                cell: LiveCellInfo {
                    tx_hash: tx_hash.unpack(),
                    tx_index: 0,
                    index: CellIndex {
                        tx_index: 0,
                        output_index: index as u32,
                    },
                    capacity: output.capacity.0,
                    data_bytes: data.len() as u64,
                    lock_hash: output.lock.code_hash,
                    number: prepare_header.number(),
                    type_hashes: None,
                },
            };
            (cell, prepare_header)
        };
        // destroy dckb
        let required_dckb = {
            let withdraw_capacity = cells
                .iter()
                .map(|cell| {
                    calculate_dao_maximum_withdraw(self.rpc_client(), cell)
                        .expect("withdraw capacity")
                })
                .sum::<u64>();
            let from_header: HeaderView = self
                .rpc_client()
                .get_header_by_number(custodian_cell.dckb_height)?
                .expect("get from")
                .into();
            let custodian_dckb_amount = calculate_dao_capacity(
                &from_header,
                &prepare_header,
                custodian_cell.dckb_amount,
                0,
            );
            withdraw_capacity - DCKB_DAO_CELL_CAPACITY - custodian_dckb_amount
        };
        // append fee cell
        let mut to_pay_fee = self.collect_sighash_cells(tx_fee)?;
        cells.append(&mut to_pay_fee);
        let dckb_cells = self.collect_dckb_live_cells(required_dckb, &prepare_header)?;
        let tx = self.build(cells).withdraw(
            self.rpc_client(),
            custodian_cell,
            dckb_cells,
            prepare_header,
        )?;
        let output_len = tx.outputs().len();
        let tx = self.install_sighash_lock(tx, &(0..output_len).collect::<Vec<_>>());
        let len = tx.inputs().len() - 2;
        self.sign(tx, 1, len)
    }

    fn collect_dckb_live_cells(
        &mut self,
        target_capacity: u64,
        tip: &HeaderView,
    ) -> Result<Vec<DCKBLiveCellInfo>, String> {
        let dckb_script_hash: H256 = self.dckb_type_hash().unpack();
        let from_address = self.transact_args().address.clone();
        let mut enough = false;
        let mut take_capacity = 0;
        let mut take_dckb = 0;
        let max_mature_number = get_max_mature_number(self.rpc_client())?;
        let mut client = HttpRpcClient::new(self.rpc_client().url().to_string());
        let terminator = |_, cell: &LiveCellInfo| {
            if !(cell
                .type_hashes
                .as_ref()
                .map(|h| &h.0 == &dckb_script_hash || &h.1 == &dckb_script_hash)
                .unwrap_or(false)
                && is_mature(cell, max_mature_number))
            {
                return (false, false);
            }

            let dckb_cell = load_dckb_data(&mut client, cell.clone(), &tip).unwrap();
            take_capacity += cell.capacity;
            take_dckb += dckb_cell.dckb_amount;
            if take_capacity >= MIN_SECP_CELL_CAPACITY && take_dckb >= target_capacity {
                enough = true;
            }
            (enough, true)
        };

        let cells: Vec<LiveCellInfo> = {
            self.with_db(|db, _| {
                db.get_live_cells_by_lock(
                    Script::from(from_address.payload()).calc_script_hash(),
                    None,
                    terminator,
                )
            })?
        };
        let mut dckb_cells: Vec<DCKBLiveCellInfo> = Vec::with_capacity(cells.len());
        let mut capacity = 0;
        for c in cells {
            let dckb_cell = load_dckb_data(self.rpc_client(), c, &tip)?;
            capacity += dckb_cell.dckb_amount;
            dckb_cells.push(dckb_cell);
            if capacity > target_capacity {
                break;
            }
        }

        if !enough {
            return Err(format!(
                "Capacity not enough: {} => ckb: {}({}) dckb: {}({})",
                from_address, take_capacity, MIN_SECP_CELL_CAPACITY, capacity, target_capacity
            ));
        }
        Ok(dckb_cells)
    }

    pub fn query_dckb_cells(
        &mut self,
        lock_hash: Byte32,
    ) -> Result<(Vec<DCKBLiveCellInfo>, HeaderView), String> {
        let dckb_cells = self.collect_dckb_cells(lock_hash)?;
        assert!(dckb_cells.iter().all(|cell| cell.data_bytes == 24));
        let tip: HeaderView = self.rpc_client().get_tip_header()?.into();
        let mut ret = Vec::with_capacity(dckb_cells.len());
        for cell in dckb_cells {
            ret.push(load_dckb_data(self.rpc_client(), cell, &tip)?);
        }
        Ok((ret, tip))
    }

    pub fn query_dao_cells(&mut self, lock_hash: Byte32) -> Result<Vec<LiveCellInfo>, String> {
        let lock_script = gen_deposit_lock_lock_script(self.dckb_env.clone(), lock_hash.unpack());
        let lock_hash = lock_script.calc_script_hash();
        let dao_cells = self.collect_dao_cells(lock_hash)?;
        let mut ret = Vec::with_capacity(dao_cells.len());
        for cell in dao_cells {
            if is_deposit_cell(self.rpc_client(), &cell)? {
                ret.push(cell);
            }
        }
        Ok(ret)
    }

    pub fn query_prepare_cells(&mut self, lock_hash: Byte32) -> Result<Vec<LiveCellInfo>, String> {
        let lock_script = gen_deposit_lock_lock_script(self.dckb_env.clone(), lock_hash.unpack());
        let lock_hash = lock_script.calc_script_hash();
        let dao_cells = self.collect_dao_cells(lock_hash)?;
        assert!(dao_cells.iter().all(|cell| cell.data_bytes == 8));
        let mut ret = Vec::with_capacity(dao_cells.len());
        for cell in dao_cells {
            if is_prepare_cell(self.rpc_client(), &cell)? {
                ret.push(cell);
            }
        }
        Ok(ret)
    }

    fn collect_dao_cells(&mut self, lock_hash: Byte32) -> Result<Vec<LiveCellInfo>, String> {
        let dao_type_hash = self.dao_type_hash().clone();
        self.with_db(|db, _| {
            let cells_by_lock = db
                .get_live_cells_by_lock(lock_hash, Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            let cells_by_code = db
                .get_live_cells_by_code(dao_type_hash.clone(), Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            cells_by_lock
                .intersection(&cells_by_code)
                .sorted_by_key(|live| (live.number, live.tx_index, live.index.output_index))
                .cloned()
                .collect::<Vec<_>>()
        })
    }

    fn collect_dckb_cells(&mut self, lock_hash: Byte32) -> Result<Vec<LiveCellInfo>, String> {
        let dckb_type_hash = self.dckb_type_hash();
        self.with_db(|db, _| {
            let cells_by_lock = db
                .get_live_cells_by_lock(lock_hash, Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            let cells_by_code = db
                .get_live_cells_by_code(dckb_type_hash.clone(), Some(0), |_, _| (false, true))
                .into_iter()
                .collect::<HashSet<_>>();
            cells_by_lock
                .intersection(&cells_by_code)
                .sorted_by_key(|live| (live.number, live.tx_index, live.index.output_index))
                .cloned()
                .collect::<Vec<_>>()
        })
    }

    fn collect_sighash_cells(&mut self, target_capacity: u64) -> Result<Vec<LiveCellInfo>, String> {
        let from_address = self.transact_args().address.clone();
        let mut enough = false;
        let mut take_capacity = 0;
        let max_mature_number = get_max_mature_number(self.rpc_client())?;
        let terminator = |_, cell: &LiveCellInfo| {
            if !(cell.type_hashes.is_none() && cell.data_bytes == 0)
                && is_mature(cell, max_mature_number)
            {
                return (false, false);
            }

            take_capacity += cell.capacity;
            if take_capacity == target_capacity
                || take_capacity >= target_capacity + MIN_SECP_CELL_CAPACITY
            {
                enough = true;
            }
            (enough, true)
        };

        let cells: Vec<LiveCellInfo> = {
            self.with_db(|db, _| {
                db.get_live_cells_by_lock(
                    Script::from(from_address.payload()).calc_script_hash(),
                    None,
                    terminator,
                )
            })?
        };

        if !enough {
            return Err(format!(
                "Capacity not enough: {} => {}({})",
                from_address, take_capacity, target_capacity,
            ));
        }
        Ok(cells)
    }

    fn build(&mut self, cells: Vec<LiveCellInfo>) -> DAOBuilder {
        let tx_fee = self.transact_args().tx_fee;
        DAOBuilder::new(
            self.genesis_info.clone(),
            self.dckb_env.clone(),
            tx_fee,
            cells,
        )
    }

    fn sign(
        &mut self,
        transaction: TransactionView,
        sig_index: usize,
        len: usize,
    ) -> Result<TransactionView, String> {
        let transaction = self.install_sighash_witness(transaction, sig_index, len)?;
        Ok(transaction)
    }

    fn install_dao_lock(&self, transaction: TransactionView, indexes: &[usize]) -> TransactionView {
        let deposit_lock_dep = {
            CellDep::new_builder()
                .out_point(self.dckb_env.dao_lock_out_point.clone())
                .dep_type(ScriptHashType::Data.into())
                .build()
        };
        let lock_script = {
            let sighash_args = self.transact_args().sighash_args();
            let genesis_info = &self.genesis_info;
            let sighash_type_hash = genesis_info.sighash_type_hash();
            let lock_script = Script::new_builder()
                .hash_type(ScriptHashType::Type.into())
                .code_hash(sighash_type_hash.clone())
                .args(Bytes::from(sighash_args.as_bytes().to_vec()).pack())
                .build();
            // last output is DCKB
            gen_deposit_lock_lock_script(
                self.dckb_env.clone(),
                lock_script.calc_script_hash().unpack(),
            )
        };
        let outputs = transaction
            .outputs()
            .into_iter()
            .enumerate()
            .map(|(i, output): (usize, CellOutput)| {
                if indexes.contains(&i) {
                    output.as_builder().lock(lock_script.clone()).build()
                } else {
                    output
                }
            })
            .collect::<Vec<_>>();
        transaction
            .as_advanced_builder()
            .set_outputs(outputs)
            .cell_dep(deposit_lock_dep)
            .build()
    }

    fn install_custodian_lock(
        &self,
        transaction: TransactionView,
        indexes: &[usize],
    ) -> TransactionView {
        let custodian_lock_dep = {
            CellDep::new_builder()
                .out_point(self.dckb_env.custodian_lock_out_point.clone())
                .dep_type(ScriptHashType::Data.into())
                .build()
        };
        let lock_script = {
            let sighash_args = self.transact_args().sighash_args();
            let genesis_info = &self.genesis_info;
            let sighash_type_hash = genesis_info.sighash_type_hash();
            let lock_script = Script::new_builder()
                .hash_type(ScriptHashType::Type.into())
                .code_hash(sighash_type_hash.clone())
                .args(Bytes::from(sighash_args.as_bytes().to_vec()).pack())
                .build();
            gen_custodian_lock_lock_script(
                self.dckb_env.clone(),
                lock_script.calc_script_hash().unpack(),
            )
        };
        let outputs = transaction
            .outputs()
            .into_iter()
            .enumerate()
            .map(|(i, output): (usize, CellOutput)| {
                if indexes.contains(&i) {
                    output.as_builder().lock(lock_script.clone()).build()
                } else {
                    output
                }
            })
            .collect::<Vec<_>>();
        transaction
            .as_advanced_builder()
            .set_outputs(outputs)
            .cell_dep(custodian_lock_dep)
            .build()
    }

    fn install_sighash_lock(
        &self,
        transaction: TransactionView,
        indexes: &[usize],
    ) -> TransactionView {
        let sighash_args = self.transact_args().sighash_args();
        let genesis_info = &self.genesis_info;
        let sighash_dep = genesis_info.sighash_dep();
        let sighash_type_hash = genesis_info.sighash_type_hash();
        let lock_script = Script::new_builder()
            .hash_type(ScriptHashType::Type.into())
            .code_hash(sighash_type_hash.clone())
            .args(Bytes::from(sighash_args.as_bytes().to_vec()).pack())
            .build();
        // install sighash for dckb cells, which started from 1
        let outputs: Vec<_> = transaction
            .outputs()
            .into_iter()
            .enumerate()
            .map(|(i, output): (usize, CellOutput)| {
                if indexes.contains(&i) {
                    output.as_builder().lock(lock_script.clone()).build()
                } else {
                    output
                }
            })
            .collect();
        transaction
            .as_advanced_builder()
            .set_outputs(outputs)
            .cell_dep(sighash_dep)
            .build()
    }

    fn install_sighash_witness(
        &self,
        transaction: TransactionView,
        sig_index: usize,
        len: usize,
    ) -> Result<TransactionView, String> {
        for output in transaction.outputs().into_iter() {
            assert!(!output.lock().args().is_empty());
        }
        for witness in transaction
            .witnesses()
            .into_iter()
            .skip(sig_index)
            .take(len)
        {
            if let Ok(w) = WitnessArgs::from_slice(witness.as_slice()) {
                assert!(w.lock().is_none());
            }
        }

        let mut witnesses = transaction
            .witnesses()
            .into_iter()
            .skip(sig_index)
            .take(len)
            .map(|w| w.unpack())
            .collect::<Vec<Bytes>>();
        let init_witness = {
            let init_witness = if witnesses[sig_index].is_empty() {
                WitnessArgs::default()
            } else {
                WitnessArgs::from_slice(&witnesses[sig_index]).map_err(|err| err.to_string())?
            };
            init_witness
                .as_builder()
                .lock(Some(Bytes::from(&[0u8; 65][..])).pack())
                .build()
        };
        let digest = {
            let mut blake2b = new_blake2b();
            blake2b.update(&transaction.hash().raw_data());
            blake2b.update(&(init_witness.as_bytes().len() as u64).to_le_bytes());
            blake2b.update(&init_witness.as_bytes());
            for other_witness in witnesses.iter().skip(1) {
                blake2b.update(&(other_witness.len() as u64).to_le_bytes());
                blake2b.update(&other_witness);
            }
            let mut message = [0u8; 32];
            blake2b.finalize(&mut message);
            H256::from(message)
        };
        let signature = {
            let account = self.transact_args().sighash_args();
            let mut signer = {
                if let Some(ref privkey) = self.transact_args().privkey {
                    get_privkey_signer(privkey.clone())
                } else {
                    let password = read_password(false, None)?;
                    get_keystore_signer(self.key_store.clone(), account.clone(), password)
                }
            };
            let accounts = vec![account].into_iter().collect::<HashSet<H160>>();
            signer(&accounts, &digest)?.expect("signer missed")
        };

        witnesses[sig_index] = init_witness
            .as_builder()
            .lock(Some(Bytes::from(signature[..].to_vec())).pack())
            .build()
            .as_bytes();
        debug_assert_eq!(witnesses.len(), len);

        Ok(transaction
            .as_advanced_builder()
            .set_witnesses(witnesses.into_iter().map(|w| w.pack()).collect::<Vec<_>>())
            .build())
    }

    fn check_db_ready(&mut self) -> Result<(), String> {
        self.with_db(|_, _| ())
    }

    fn with_db<F, T>(&mut self, func: F) -> Result<T, String>
    where
        F: FnOnce(IndexDatabase, &mut HttpRpcClient) -> T,
    {
        let network_type = get_network_type(self.rpc_client)?;
        let genesis_info = self.genesis_info.clone();
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        with_index_db(&self.index_dir.clone(), genesis_hash, |backend, cf| {
            let db = IndexDatabase::from_db(backend, cf, network_type, genesis_info, false)?;
            Ok(func(db, self.rpc_client()))
        })
        .map_err(|_err| {
            format!(
                "Index database may not ready, sync process: {}",
                self.index_controller.state().read().to_string()
            )
        })
    }

    fn transact_args(&self) -> &TransactArgs {
        self.transact_args.as_ref().expect("exist")
    }

    fn dao_type_hash(&self) -> &Byte32 {
        self.genesis_info.dao_type_hash()
    }

    fn dckb_type_hash(&self) -> Byte32 {
        self.dckb_env.dckb_code_hash.pack()
    }

    pub(crate) fn rpc_client(&mut self) -> &mut HttpRpcClient {
        &mut self.rpc_client
    }
}

// TODO remove the duplicated function later
fn get_keystore_signer(key_store: KeyStore, account: H160, password: String) -> SignerFn {
    Box::new(move |lock_args: &HashSet<H160>, message: &H256| {
        if lock_args.contains(&account) {
            if message == &h256!("0x0") {
                Ok(Some([0u8; 65]))
            } else {
                key_store
                    .sign_recoverable_with_password(&account, &[], message, password.as_bytes())
                    .map(|signature| Some(serialize_signature(&signature)))
                    .map_err(|err| err.to_string())
            }
        } else {
            Ok(None)
        }
    })
}

fn take_by_out_points(
    cells: Vec<LiveCellInfo>,
    out_points: &[OutPoint],
) -> Result<Vec<LiveCellInfo>, String> {
    let mut set = out_points.iter().collect::<HashSet<_>>();
    let takes = cells
        .into_iter()
        .filter(|cell| set.remove(&cell.out_point()))
        .collect::<Vec<_>>();
    if !set.is_empty() {
        return Err(format!("cells are not found: {:?}", set));
    }
    Ok(takes)
}

fn is_deposit_cell(
    rpc_client: &mut HttpRpcClient,
    dao_cell: &LiveCellInfo,
) -> Result<bool, String> {
    get_cell_data(rpc_client, dao_cell)
        .map(|content| LittleEndian::read_u64(&content.as_bytes()[0..8]) == 0)
}

fn is_prepare_cell(
    rpc_client: &mut HttpRpcClient,
    dao_cell: &LiveCellInfo,
) -> Result<bool, String> {
    get_cell_data(rpc_client, dao_cell)
        .map(|content| LittleEndian::read_u64(&content.as_bytes()[0..8]) != 0)
}

fn get_cell_data(
    rpc_client: &mut HttpRpcClient,
    dao_cell: &LiveCellInfo,
) -> Result<JsonBytes, String> {
    let cell_info = rpc_client
        .get_live_cell(dao_cell.out_point(), true)?
        .cell
        .ok_or_else(|| format!("cell is not found: {:?}", dao_cell.out_point()))?;
    Ok(cell_info.data.unwrap().content)
}

fn gen_custodian_lock_lock_script(env: DCKBENV, owner_lock_hash: [u8; 32]) -> Script {
    let custodian_lock_code_hash = env.custodian_lock_code_hash;
    Script::new_builder()
        .args(Bytes::from(owner_lock_hash.to_vec()).pack())
        .code_hash(custodian_lock_code_hash.pack())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

fn gen_deposit_lock_lock_script(env: DCKBENV, refund_lock_hash: [u8; 32]) -> Script {
    let dckb_type_hash: [u8; 32] = dckb_script(env.clone()).calc_script_hash().unpack();
    let dao_lock_code_hash = env.dao_lock_code_hash;
    let args: [u8; 64] = {
        let mut args = [0u8; 64];
        args[..32].copy_from_slice(&dckb_type_hash);
        args[32..].copy_from_slice(&refund_lock_hash);
        args
    };
    Script::new_builder()
        .args(Bytes::from(args.to_vec()).pack())
        .code_hash(dao_lock_code_hash.pack())
        .hash_type(ScriptHashType::Data.into())
        .build()
}
