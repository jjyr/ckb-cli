use ckb_sdk::NetworkType;
use ckb_types::{packed::OutPoint, prelude::*};
use faster_hex::hex_decode;

#[derive(Debug, Clone)]
pub struct DCKBENV {
    pub dao_lock_out_point: OutPoint,
    pub dao_lock_code_hash: [u8; 32],
    pub dckb_out_point: OutPoint,
    pub dckb_code_hash: [u8; 32],
    pub custodian_lock_out_point: OutPoint,
    pub custodian_lock_code_hash: [u8; 32],
}

impl DCKBENV {
    pub fn from_network(_network: NetworkType) -> Self {
        let mut tx_hash = [0u8; 32];
        hex_decode(
            b"5f2615f31e5c15e037e23a51e173a4c9856caa65a41301269fa12b33a9d58896",
            &mut tx_hash,
        )
        .expect("dehex");
        let dckb_out_point = OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(0u32.pack())
            .build();
        let dao_lock_out_point = OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(1u32.pack())
            .build();
        let custodian_lock_out_point = OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(2u32.pack())
            .build();
        let mut dckb_code_hash = [0u8; 32];
        hex_decode(
            b"501fd8267f7448eda4f8b1d0245174c7fc163c1b2f149346abc097b319a1c624",
            &mut dckb_code_hash,
        )
        .expect("dehex");
        let mut dao_lock_code_hash = [0u8; 32];
        hex_decode(
            b"6e7cc0db0b2e932b2450a689017c96d06ae6ed08b6b7c60e92f8f52e72bb3219",
            &mut dao_lock_code_hash,
        )
        .expect("dehex");
        let mut custodian_lock_code_hash = [0u8; 32];
        hex_decode(
            b"1877350a85ab2325ef4b9eaabf54782561ad6a5b6cd206e57a8d478b430d81dd",
            &mut custodian_lock_code_hash,
        )
        .expect("dehex");
        DCKBENV {
            dao_lock_out_point,
            dao_lock_code_hash,
            dckb_out_point,
            dckb_code_hash,
            custodian_lock_out_point,
            custodian_lock_code_hash,
        }
    }
}
