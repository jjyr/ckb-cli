use self::builder::{dckb_script, DAOBuilder};
use self::command::TransactArgs;
use crate::utils::index::IndexController;
use crate::utils::other::{
    get_max_mature_number, get_network_type, get_privkey_signer, is_mature, read_password,
    serialize_signature,
};
use byteorder::{ByteOrder, LittleEndian};
use ckb_hash::new_blake2b;
use ckb_index::{with_index_db, IndexDatabase, LiveCellInfo};
use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{
    constants::{MIN_SECP_CELL_CAPACITY, SIGHASH_TYPE_HASH},
    wallet::KeyStore,
    GenesisInfo, HttpRpcClient, NetworkType, SignerFn,
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
const PROXY_LOCK_CAPACITY: u64 = 69_00000000;

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
        let tx = self.install_deposit_lock(tx, &[0]);
        let output_len = tx.outputs().len();
        let tx = self.install_sighash_lock(tx, &(1..output_len).collect::<Vec<_>>());
        let tx = self.sign(tx, 0)?;
        Ok(tx)
    }

    pub fn transfer(
        &mut self,
        dckb_amount: u64,
        target_lock: Script,
    ) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let tx_fee = self.transact_args().tx_fee;
        let target_capacity = DCKB_CAPACITY + tx_fee;
        let live_cells = self.collect_sighash_cells(target_capacity)?;
        let (cells, tip) = self.collect_dckb_live_cells(dckb_amount)?;
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
        let tx = self.sign(tx, 0)?;
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
        let mut to_pay_fee = self.collect_sighash_cells(tx_fee)?;
        cells.append(&mut to_pay_fee);
        let (dckb_cells, tip_header) = self.collect_dckb_live_cells(target_capacity)?;
        let tx = self
            .build(cells)
            .prepare(self.rpc_client(), dckb_cells, tip_header)?;
        let output_len = tx.outputs().len();
        let tx = self.install_sighash_lock(tx, &(1..output_len).collect::<Vec<_>>());
        self.sign(tx, 1)
    }

    pub fn withdraw(&mut self, out_points: Vec<OutPoint>) -> Result<TransactionView, String> {
        self.check_db_ready()?;
        let tx_fee = self.transact_args().tx_fee;
        let lock_hash = self.transact_args().lock_hash();
        let mut cells = {
            let deposit_cells = self.query_prepare_cells(lock_hash.clone())?;
            take_by_out_points(deposit_cells, &out_points)?
        };
        // destroy dckb
        let target_capacity = cells.iter().map(|cell| cell.capacity).sum::<u64>();
        // aapend fee cell
        let mut to_pay_fee = self.collect_sighash_cells(tx_fee)?;
        cells.append(&mut to_pay_fee);
        let (dckb_cells, tip_header) = self.collect_dckb_live_cells(target_capacity)?;
        // let tx = self.build(cells).withdraw(self.rpc_client(), dckb_cells, tip_header)?;
        // let output_len = tx.outputs().len();
        // let tx = self.install_sighash_lock(tx, &(0..output_len).collect::<Vec<_>>());
        // self.sign(tx, 1)
        Ok(unreachable!())
    }

    fn collect_dckb_live_cells(
        &mut self,
        target_capacity: u64,
    ) -> Result<(Vec<DCKBLiveCellInfo>, HeaderView), String> {
        let dckb_script_hash: H256 = self.dckb_type_hash().unpack();
        let from_address = self.transact_args().address.clone();
        let mut enough = false;
        let mut take_capacity = 0;
        let mut take_dckb = 0;
        let max_mature_number = get_max_mature_number(self.rpc_client())?;
        let tip: HeaderView = self.rpc_client().get_tip_header()?.into();
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
                from_address, take_capacity, MIN_SECP_CELL_CAPACITY, take_dckb, target_capacity
            ));
        }
        Ok((dckb_cells, tip))
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
                "Capacity not enough: {} => {}",
                from_address, take_capacity,
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
    ) -> Result<TransactionView, String> {
        let transaction = self.install_sighash_witness(transaction, sig_index)?;
        Ok(transaction)
    }

    fn install_deposit_lock(
        &self,
        transaction: TransactionView,
        indexes: &[usize],
    ) -> TransactionView {
        let deposit_lock_dep = {
            CellDep::new_builder()
                .out_point(self.dckb_env.deposit_lock_out_point.clone())
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
    ) -> Result<TransactionView, String> {
        for output in transaction.outputs().into_iter() {
            assert!(!output.lock().args().is_empty());
        }
        for witness in transaction.witnesses() {
            if let Ok(w) = WitnessArgs::from_slice(witness.as_slice()) {
                assert!(w.lock().is_none());
            }
        }

        let mut witnesses = transaction
            .witnesses()
            .into_iter()
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
            for other_witness in witnesses.iter().skip(sig_index + 1) {
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

fn gen_deposit_lock_lock_script(env: DCKBENV, refund_lock_hash: [u8; 32]) -> Script {
    let dckb_type_hash: [u8; 32] = dckb_script(env.clone()).calc_script_hash().unpack();
    let deposit_lock_code_hash = env.deposit_lock_code_hash;
    let args: [u8; 64] = {
        let mut args = [0u8; 64];
        args[..32].copy_from_slice(&dckb_type_hash);
        args[32..].copy_from_slice(&refund_lock_hash);
        args
    };
    Script::new_builder()
        .args(Bytes::from(args.to_vec()).pack())
        .code_hash(deposit_lock_code_hash.pack())
        .hash_type(ScriptHashType::Data.into())
        .build()
}

fn load_dckb_data(
    rpc_client: &mut HttpRpcClient,
    cell: LiveCellInfo,
    tip: &HeaderView,
) -> Result<DCKBLiveCellInfo, String> {
    const DAO_OCCUPIED_CAPACITY: u64 = 146_00000000;

    fn calculate_dao_capacity(
        from_header: &HeaderView,
        to_header: &HeaderView,
        original_capacity: u64,
        occupied_capacity: u64,
    ) -> u64 {
        let from_ar = {
            let dao: [u8; 32] = from_header.dao().unpack();
            let mut buf = [0u8; 8];
            buf.clone_from_slice(&dao[8..16]);
            u64::from_le_bytes(buf)
        };
        let to_ar = {
            let dao: [u8; 32] = to_header.dao().unpack();
            let mut buf = [0u8; 8];
            buf.clone_from_slice(&dao[8..16]);
            u64::from_le_bytes(buf)
        };

        if original_capacity < occupied_capacity {
            return original_capacity;
        }
        let counted_capacity = original_capacity - occupied_capacity;
        let withdraw_counted_capacity =
            (counted_capacity as u128 * to_ar as u128 / from_ar as u128) as u64;
        withdraw_counted_capacity + occupied_capacity
    }

    let tx = rpc_client
        .get_transaction(cell.tx_hash.clone())?
        .expect("tx");
    let data = tx.transaction.inner.outputs_data[cell.index.output_index as usize].as_bytes();
    let (dckb_amount, dckb_number) = {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&data[..16]);
        let dckb_amount = u128::from_le_bytes(buf) as u64;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[16..]);
        let dckb_number = u64::from_le_bytes(buf);
        (dckb_amount, dckb_number)
    };
    let cell_header: HeaderView = if dckb_number == 0 {
        rpc_client
            .get_header_by_number(cell.number)?
            .expect("header")
            .into()
    } else {
        rpc_client
            .get_header_by_number(dckb_number)?
            .expect("header")
            .into()
    };
    let dckb_amount = calculate_dao_capacity(&cell_header, tip, dckb_amount, 0);

    let dckb_height: u64 = tip.data().raw().number().unpack();
    Ok(DCKBLiveCellInfo {
        dckb_amount,
        dckb_height,
        cell,
    })
}
