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
            b"ae632d9b8e4beea763c4580c07628df10b70a726b6120460435b4470c751fcec",
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
            b"63f7b0f104c7c4953763577d1a68e8424fdcad595c670484b006babe214e0e67",
            &mut dckb_code_hash,
        )
        .expect("dehex");
        let mut deposit_lock_code_hash = [0u8; 32];
        hex_decode(
            b"3bb2f58c4e9e23757e7b586039951e1bfc243c9d1a68ec0f787f2448e8f1e1b2",
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
