use ckb_sdk::NetworkType;
use ckb_types::{packed::OutPoint, prelude::*};
use faster_hex::hex_decode;

#[derive(Debug, Clone)]
pub struct DCKBENV {
    pub deposit_lock_out_point: OutPoint,
    pub deposit_lock_code_hash: [u8; 32],
    pub dckb_out_point: OutPoint,
    pub dckb_code_hash: [u8; 32],
}

impl DCKBENV {
    pub fn from_network(_network: NetworkType) -> Self {
        let mut tx_hash = [0u8; 32];
        hex_decode(
            b"701a2bbc7effe1a747a8b98594cbe2b770fc77b94a09549e6e0ab504e6d377be",
            &mut tx_hash,
        )
        .expect("dehex");
        let dckb_out_point = OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(0u32.pack())
            .build();
        let deposit_lock_out_point = OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(1u32.pack())
            .build();
        let mut dckb_code_hash = [0u8; 32];
        hex_decode(
            b"e85be04bc5d4a35b69a3bfed5cbc790a65f5c8c91a7a934982f8832417aaabac",
            &mut dckb_code_hash,
        )
        .expect("dehex");
        let mut deposit_lock_code_hash = [0u8; 32];
        hex_decode(
            b"819a0a01c9b7a96f43ae5d340ccc08ddc9d69e16e8456334edaba4f983d67339",
            &mut deposit_lock_code_hash,
        )
        .expect("dehex");
        DCKBENV {
            deposit_lock_out_point,
            deposit_lock_code_hash,
            dckb_out_point,
            dckb_code_hash,
        }
    }
}
