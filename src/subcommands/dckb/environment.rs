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
            b"452b2e5046f81b4fc8940292010235e58925594c04536a9a9117447c8d1665d4",
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
            b"4eeadcbfc047ad162bcb3ecec312054a686fe11813f9c70ce3915cad1a9fd36f",
            &mut dckb_code_hash,
        )
        .expect("dehex");
        let mut deposit_lock_code_hash = [0u8; 32];
        hex_decode(
            b"ae167e9866128f6489d291007746baffa9ee5fc12f8fde6cde729671313642a5",
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
