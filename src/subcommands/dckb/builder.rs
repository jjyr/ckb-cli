use super::environment::DCKBENV;
use super::util::minimal_unlock_point;
use super::{
    DCKBLiveCellInfo, DCKB_CAPACITY, DCKB_DAO_CELL_CAPACITY, PROXY_LOCK_CAPACITY,
    SECP256K1_CAPACITY,
};
use crate::subcommands::dckb::util::calculate_dao_maximum_withdraw4;
use ckb_index::LiveCellInfo;
use ckb_sdk::{constants::MIN_SECP_CELL_CAPACITY, GenesisInfo, HttpRpcClient, Since, SinceType};
use ckb_types::core::Capacity;
use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use std::cmp::max;
use std::collections::HashSet;

// NOTE: We assume all inputs are from same account
#[derive(Debug)]
pub(crate) struct DAOBuilder {
    genesis_info: GenesisInfo,
    dckb_env: DCKBENV,
    tx_fee: u64,
    live_cells: Vec<LiveCellInfo>,
}

impl DAOBuilder {
    pub(crate) fn new(
        genesis_info: GenesisInfo,
        dckb_env: DCKBENV,
        tx_fee: u64,
        live_cells: Vec<LiveCellInfo>,
    ) -> Self {
        Self {
            genesis_info,
            dckb_env,
            tx_fee,
            live_cells,
        }
    }

    pub(crate) fn transfer(
        &self,
        rpc_client: &mut HttpRpcClient,
        dckb_live_cells: Vec<DCKBLiveCellInfo>,
        tip: HeaderView,
        dckb_amount: u64,
        target_capacity: u64,
        target_lock: Script,
    ) -> Result<TransactionView, String> {
        let genesis_info = &self.genesis_info;
        let inputs = dckb_live_cells
            .iter()
            .map(|txo| CellInput::new(txo.cell.out_point(), 0))
            .chain(
                self.live_cells
                    .iter()
                    .map(|cell| CellInput::new(cell.out_point(), 0)),
            )
            .collect::<Vec<_>>();

        let input_dckb_amount = dckb_live_cells
            .iter()
            .map(|txo| txo.dckb_amount)
            .sum::<u64>();
        let change_dckb_amount = input_dckb_amount - dckb_amount;

        let input_capacity = self
            .live_cells
            .iter()
            .map(|txo| txo.capacity)
            .chain(dckb_live_cells.iter().map(|cell| cell.cell.capacity))
            .sum::<u64>();
        let change_capacity = input_capacity
            - target_capacity
            - Capacity::bytes(61).unwrap().as_u64()
            - 2 * DCKB_CAPACITY;

        let (dckb_output, dckb_output_data) = {
            // NOTE: Here give null lock script to the output. It's caller's duty to fill the lock
            gen_dckb_cell(self.dckb_env.clone(), dckb_amount, tip.number())
        };
        // set transfer target
        let dckb_output = dckb_output.as_builder().lock(target_lock).build();
        // change cells
        let (dckb_change, dckb_change_data) =
            gen_dckb_cell(self.dckb_env.clone(), change_dckb_amount, tip.number());
        let change = CellOutput::new_builder()
            .capacity(change_capacity.pack())
            .build();
        let cell_deps = vec![genesis_info.dao_dep(), self.dckb_dep()];
        let (dckb_lives_cells_with_number, mut header_deps) =
            dckb_cell_deps(rpc_client, dckb_live_cells);
        header_deps.push(tip.clone());
        header_deps.dedup_by_key(|h| h.number());
        let mut tx = TransactionBuilder::default()
            .inputs(inputs)
            .output(dckb_output)
            .output_data(dckb_output_data.pack())
            .cell_deps(cell_deps)
            .header_deps(header_deps.iter().map(|h| h.hash()))
            .build();

        if change_dckb_amount > 0 {
            tx = tx
                .as_advanced_builder()
                .output(dckb_change)
                .output_data(dckb_change_data.pack())
                .build();
        }
        if change_capacity > 0 {
            tx = tx
                .as_advanced_builder()
                .output(change)
                .output_data(Default::default())
                .build();
        }
        let mut witnesses =
            build_witness_for_ckb_cells(dckb_lives_cells_with_number, &header_deps, &tip);
        for _i in witnesses.len()..max(tx.inputs().len(), tx.outputs().len()) {
            witnesses.push(WitnessArgs::default().as_bytes().pack());
        }
        let tx = tx.as_advanced_builder().witnesses(witnesses).build();
        let output_capacity = tx
            .outputs()
            .into_iter()
            .map(|o| {
                let c: Capacity = o.capacity().unpack();
                c.as_u64()
            })
            .sum::<u64>();
        let occupied_capacity = tx
            .outputs()
            .into_iter()
            .zip(tx.outputs_data().into_iter())
            .map(|(o, data)| {
                let c: Capacity = o
                    .occupied_capacity(Capacity::bytes(data.len()).unwrap())
                    .unwrap();
                c.as_u64()
            })
            .sum::<u64>();
        assert_eq!(input_dckb_amount, dckb_amount + change_dckb_amount);
        println!("occupied capacity {}", occupied_capacity);
        println!(
            "tx inputs capacity {} outputs capacity {}",
            input_capacity, output_capacity
        );
        println!("tx change capacity {} ", change_capacity);
        println!(
            "tx inputs capacity - outputs capacity {}",
            input_capacity - output_capacity
        );
        Ok(tx)
    }

    pub(crate) fn deposit(&self, deposit_capacity: u64) -> Result<TransactionView, String> {
        let genesis_info = &self.genesis_info;
        let inputs = self
            .live_cells
            .iter()
            .map(|txo| CellInput::new(txo.out_point(), 0))
            .collect::<Vec<_>>();
        let (output, output_data) = {
            // NOTE: Here give null lock script to the output. It's caller's duty to fill the lock
            let output = CellOutput::new_builder()
                .capacity(deposit_capacity.pack())
                .type_(Some(dao_type_script(&self.genesis_info)?).pack())
                .build();
            let output_data = Bytes::from(&[0u8; 8][..]).pack();
            (output, output_data)
        };

        let (dckb_output, dckb_output_data) = {
            // NOTE: Here give null lock script to the output. It's caller's duty to fill the lock
            gen_dckb_cell(
                self.dckb_env.clone(),
                deposit_capacity - DCKB_DAO_CELL_CAPACITY,
                0,
            )
        };
        let dckb_capacity: Capacity = dckb_output.capacity().unpack();
        let cell_deps = vec![genesis_info.dao_dep(), self.dckb_dep()];
        let witnesses = (0..max(inputs.len(), 2))
            .into_iter()
            .map(|_| Default::default())
            .collect::<Vec<_>>();
        {
            let secp256k1_script_hash = dckb_output.lock().calc_script_hash();
            let dao_script_hash = output.type_().to_opt().unwrap().calc_script_hash();
            let dckb_script_hash = dckb_output.type_().to_opt().unwrap().calc_script_hash();
            println!("secp256k1: {}", secp256k1_script_hash);
            let raw_dao_script_hash: [u8; 32] = dao_script_hash.unpack();
            println!("dao: {} raw: {:?}", dao_script_hash, raw_dao_script_hash);
            println!("dckb: {}", dckb_script_hash);
        }
        let tx = TransactionBuilder::default()
            .inputs(inputs)
            .output(output)
            .output_data(output_data)
            .output(dckb_output)
            .output_data(dckb_output_data.pack())
            .cell_deps(cell_deps)
            .witnesses(witnesses);

        let input_capacity = self.live_cells.iter().map(|txo| txo.capacity).sum::<u64>();
        let change_capacity =
            input_capacity - deposit_capacity - self.tx_fee - dckb_capacity.as_u64();
        if change_capacity >= MIN_SECP_CELL_CAPACITY {
            let change = CellOutput::new_builder()
                .capacity(change_capacity.pack())
                .build();
            Ok(tx.output(change).output_data(Default::default()).build())
        } else {
            Ok(tx.build())
        }
    }

    pub(crate) fn prepare(
        &self,
        rpc_client: &mut HttpRpcClient,
        dckb_cells: Vec<DCKBLiveCellInfo>,
        tip: HeaderView,
    ) -> Result<TransactionView, String> {
        let genesis_info = &self.genesis_info;
        let dao_type_hash = genesis_info.dao_type_hash();
        let mut deposit_cells: Vec<LiveCellInfo> = Vec::new();
        let mut change_cells: Vec<LiveCellInfo> = Vec::new();
        // calculate deposit capacity
        for cell in self.live_cells.iter() {
            if cell
                .type_hashes
                .as_ref()
                .map(|(code_hash, _)| &code_hash.pack() == dao_type_hash)
                .unwrap_or(false)
            {
                deposit_cells.push(cell.clone());
            } else {
                change_cells.push(cell.clone());
            }
        }
        let dckb_destroy_target =
            deposit_cells.iter().map(|cell| cell.capacity).sum::<u64>() - DCKB_DAO_CELL_CAPACITY;
        let dckb_capacity = dckb_cells.iter().map(|cell| cell.dckb_amount).sum::<u64>();
        let dckb_change_capacity = dckb_capacity - dckb_destroy_target;
        let deposit_txo_headers = {
            let deposit_out_points = deposit_cells
                .iter()
                .map(|txo| txo.out_point())
                .collect::<Vec<_>>();
            self.txo_headers(rpc_client, deposit_out_points)?
        };

        let inputs = self
            .live_cells
            .iter()
            .chain(dckb_cells.iter().map(|cell| &cell.cell))
            .map(|txo| CellInput::new(txo.out_point(), 0))
            .collect::<Vec<_>>();
        // NOTE: Prepare output has the same capacity, type script, lock script as the input
        let outputs = deposit_txo_headers
            .iter()
            .map(|(_, output, _)| output.clone())
            .collect::<Vec<_>>();
        let outputs_data = deposit_txo_headers.iter().map(|(_, _, header)| {
            let deposit_number = header.number();
            Bytes::from(deposit_number.to_le_bytes().to_vec()).pack()
        });
        let cell_deps = vec![
            genesis_info.dao_dep(),
            self.dckb_dep(),
            self.deposit_lock_dep(),
        ];
        let tx = TransactionBuilder::default()
            .inputs(inputs)
            .outputs(outputs)
            .cell_deps(cell_deps)
            .outputs_data(outputs_data)
            .build();

        let proxy_lock_cell = CellOutput::new_builder()
            .capacity(PROXY_LOCK_CAPACITY.pack())
            .build();
        let proxy_lock_data: Bytes = {
            let deposit_lock_script_hash: [u8; 32] = self.live_cells[0].lock_hash.clone().into();
            deposit_lock_script_hash[..8].to_vec().into()
        };

        let change_capacity = change_cells.iter().map(|txo| txo.capacity).sum::<u64>()
            - self.tx_fee
            - DCKB_CAPACITY
            - PROXY_LOCK_CAPACITY
            - SECP256K1_CAPACITY;
        let change = CellOutput::new_builder()
            .capacity(change_capacity.pack())
            .build();
        let dckb_change = CellOutput::new_builder()
            .capacity(DCKB_CAPACITY.pack())
            .type_(Some(dckb_script(self.dckb_env.clone())).pack())
            .build();
        let dckb_change_data = dckb_data(dckb_change_capacity.into(), tip.number());

        let (dckb_cells_with_number, mut header_deps) = dckb_cell_deps(rpc_client, dckb_cells);
        header_deps.extend(deposit_txo_headers.into_iter().map(|(_, _, header)| header));
        header_deps.push(tip.clone());
        header_deps.dedup_by_key(|h| h.hash());

        let lock_proxy_cell_index: u8 = tx.outputs().len() as u8;
        let dckb_witnesses =
            build_witness_for_ckb_cells(dckb_cells_with_number, &header_deps, &tip);
        let mut witnesses = vec![WitnessArgs::default()
            .as_builder()
            .lock(Some(Bytes::from(vec![lock_proxy_cell_index])).pack())
            .build()
            .as_bytes()
            .pack()];
        witnesses.extend(
            (witnesses.len()..self.live_cells.len())
                .map(|_| WitnessArgs::default().as_bytes().pack()),
        );
        witnesses.extend(dckb_witnesses.into_iter());
        assert_eq!(tx.inputs().len(), witnesses.len());

        let tx = tx
            .as_advanced_builder()
            .output(proxy_lock_cell)
            .output_data(proxy_lock_data.pack())
            .output(change)
            .output_data(Default::default())
            .output(dckb_change)
            .output_data(dckb_change_data.pack())
            .header_deps(header_deps.into_iter().map(|h| h.hash()))
            .witnesses(witnesses)
            .build();
        println!(
            "input dckb {} change dckb {}",
            dckb_capacity, dckb_change_capacity
        );
        Ok(tx)
    }

    pub(crate) fn withdraw(
        &self,
        rpc_client: &mut HttpRpcClient,
    ) -> Result<TransactionView, String> {
        let genesis_info = &self.genesis_info;
        let prepare_txo_headers = {
            let prepare_out_points = self
                .live_cells
                .iter()
                .map(|txo| txo.out_point())
                .collect::<Vec<_>>();
            self.txo_headers(rpc_client, prepare_out_points)?
        };
        let deposit_txo_headers = {
            let deposit_out_points = prepare_txo_headers
                .iter()
                .map(|(out_point, _, _)| {
                    let tx: packed::Transaction = rpc_client
                        .get_transaction(out_point.tx_hash().unpack())?
                        .expect("checked above")
                        .transaction
                        .inner
                        .into();
                    let tx = tx.into_view();
                    let input = tx
                        .inputs()
                        .get(out_point.index().unpack())
                        .expect("prepare out_point has the same index with deposit input");
                    Ok(input.previous_output())
                })
                .collect::<Result<Vec<_>, String>>()?;
            self.txo_headers(rpc_client, deposit_out_points)?
        };

        let inputs = deposit_txo_headers
            .iter()
            .zip(prepare_txo_headers.iter())
            .map(|((_, _, deposit_header), (out_point, _, prepare_header))| {
                let minimal_unlock_point = minimal_unlock_point(deposit_header, prepare_header);
                let since = Since::new(
                    SinceType::EpochNumberWithFraction,
                    minimal_unlock_point.full_value(),
                    false,
                );
                CellInput::new(out_point.clone(), since.value())
            });
        let total_capacity = deposit_txo_headers
            .iter()
            .zip(prepare_txo_headers.iter())
            .map(|((_, output, deposit_header), (_, _, prepare_header))| {
                const DAO_OUTPUT_DATA_LEN: usize = 8;
                let occupied_capacity = output
                    .occupied_capacity(Capacity::bytes(DAO_OUTPUT_DATA_LEN).unwrap())
                    .unwrap();
                calculate_dao_maximum_withdraw4(
                    deposit_header,
                    prepare_header,
                    output,
                    occupied_capacity.as_u64(),
                )
            })
            .sum::<u64>();
        let output_capacity = total_capacity - self.tx_fee;
        let output = CellOutput::new_builder()
            .capacity(output_capacity.pack())
            .build();
        let cell_deps = vec![genesis_info.dao_dep()];
        let header_deps = deposit_txo_headers
            .iter()
            .chain(prepare_txo_headers.iter())
            .map(|(_, _, header)| header.hash())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let witnesses = deposit_txo_headers
            .iter()
            .map(|(_, _, header)| {
                let index = header_deps
                    .iter()
                    .position(|hash| hash == &header.hash())
                    .unwrap() as u64;
                WitnessArgs::new_builder()
                    .input_type(Some(Bytes::from(index.to_le_bytes().to_vec())).pack())
                    .build()
                    .as_bytes()
                    .pack()
            })
            .collect::<Vec<_>>();
        Ok(TransactionBuilder::default()
            .inputs(inputs)
            .output(output)
            .cell_deps(cell_deps)
            .header_deps(header_deps)
            .witnesses(witnesses)
            .output_data(Default::default())
            .build())
    }

    fn txo_headers(
        &self,
        rpc_client: &mut HttpRpcClient,
        out_points: Vec<OutPoint>,
    ) -> Result<Vec<(OutPoint, CellOutput, HeaderView)>, String> {
        let mut ret = Vec::new();
        for out_point in out_points.into_iter() {
            let tx_status = rpc_client
                .get_transaction(out_point.tx_hash().unpack())?
                .ok_or_else(|| "get_transaction None".to_string())?;
            let tx: packed::Transaction = tx_status.transaction.inner.into();
            let tx = tx.into_view();
            let header: HeaderView = {
                let block_hash = tx_status
                    .tx_status
                    .block_hash
                    .ok_or_else(|| "Tx is not on-chain".to_owned())?;
                rpc_client
                    .get_header(block_hash)?
                    .expect("checked above")
                    .into()
            };

            let output_index: u32 = out_point.index().unpack();
            let output = tx
                .outputs()
                .get(output_index as usize)
                .ok_or_else(|| "OutPoint is out of index".to_owned())?;
            ret.push((out_point, output, header))
        }
        Ok(ret)
    }

    fn dckb_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.dckb_env.dckb_out_point.clone())
            .dep_type(ScriptHashType::Data.into())
            .build()
    }

    fn deposit_lock_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.dckb_env.deposit_lock_out_point.clone())
            .dep_type(ScriptHashType::Data.into())
            .build()
    }
}

fn dao_type_script(genesis_info: &GenesisInfo) -> Result<Script, String> {
    Ok(Script::new_builder()
        .hash_type(ScriptHashType::Type.into())
        .code_hash(genesis_info.dao_type_hash().clone())
        .build())
}

pub fn dckb_script(env: DCKBENV) -> Script {
    let code_hash = env.dckb_code_hash;
    Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(ScriptHashType::Data.into())
        .build()
}
fn decode_dckb_data(data: Bytes) -> (u64, u64) {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&data[0..16]);
    let dckb = u128::from_le_bytes(buf);
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[16..]);
    let number = u64::from_le_bytes(buf);
    (dckb as u64, number)
}

fn dckb_data(ckb: u128, block_number: u64) -> Bytes {
    let mut data = [0u8; 24];
    data[..16].copy_from_slice(&ckb.to_le_bytes()[..]);
    data[16..].copy_from_slice(&block_number.to_le_bytes()[..]);
    data.to_vec().into()
}
fn gen_dckb_cell(env: DCKBENV, capacity: u64, height: u64) -> (CellOutput, Bytes) {
    let type_ = dckb_script(env);
    let cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(DCKB_CAPACITY).pack())
        .type_(Some(type_).pack())
        .build();
    let data = dckb_data(capacity.into(), height);
    (cell, data)
}

fn dckb_cell_deps(
    rpc_client: &mut HttpRpcClient,
    dckb_live_cells: Vec<DCKBLiveCellInfo>,
) -> (Vec<(DCKBLiveCellInfo, u64)>, Vec<HeaderView>) {
    let dckb_lives_cells_with_number: Vec<_> = dckb_live_cells
        .into_iter()
        .map(|cell| {
            let tx = rpc_client
                .get_transaction(cell.cell.tx_hash.clone())
                .unwrap()
                .unwrap();
            let i: u32 = cell.cell.out_point().index().unpack();
            let data = tx
                .transaction
                .inner
                .outputs_data
                .get(i as usize)
                .as_ref()
                .unwrap()
                .as_bytes()
                .to_vec()
                .into();
            let (_, mut number) = decode_dckb_data(data);
            if number == 0 {
                number = cell.cell.number;
            }
            (cell, number)
        })
        .collect();
    let header_deps: Vec<_> = dckb_lives_cells_with_number
        .iter()
        .map(|(_cell, number)| {
            let h: HeaderView = rpc_client
                .get_header_by_number(*number)
                .unwrap()
                .unwrap()
                .into();
            h
        })
        .collect();
    (dckb_lives_cells_with_number, header_deps)
}

fn build_witness_for_ckb_cells(
    dckb_lives_cells_with_number: Vec<(DCKBLiveCellInfo, u64)>,
    header_deps: &[HeaderView],
    align_target: &HeaderView,
) -> Vec<packed::Bytes> {
    let mut witnesses = Vec::new();
    for i in 0..dckb_lives_cells_with_number.len() {
        let number = dckb_lives_cells_with_number[i].1;
        let header_index = header_deps
            .iter()
            .position(|h| h.number() == number)
            .unwrap();
        let input_type = if i == 0 {
            let align_target_index = header_deps
                .iter()
                .position(|h| h.number() == align_target.number())
                .unwrap();
            Bytes::from(vec![header_index as u8, align_target_index as u8])
        } else {
            Bytes::from(vec![header_index as u8])
        };
        witnesses.push(
            WitnessArgs::new_builder()
                .input_type(Some(input_type).pack())
                .build()
                .as_bytes()
                .pack(),
        );
    }
    witnesses
}
