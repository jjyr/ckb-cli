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
        let mut dckb_tx_hash = [0u8; 32];
        hex_decode(
            b"06d4ac070827afa2a88a3583dea85f23309eee9f83ddcaa1ca521ee5f467b5f5",
            &mut dckb_tx_hash,
        )
        .expect("dehex");
        let mut dao_lock_tx_hash = [0u8; 32];
        hex_decode(
            b"69f4606d63f22a9b3b1ec11116ba4eba11351fe1def4d30e09aa2b8280494b23",
            &mut dao_lock_tx_hash,
        )
        .expect("dehex");
        let mut custodian_lock_tx_hash = [0u8; 32];
        hex_decode(
            b"8179b3965e324c336b93a3bf4d5ab71470fcec1b99de37a8efd1909ff6b3f12d",
            &mut custodian_lock_tx_hash,
        )
        .expect("dehex");
        let dckb_out_point = OutPoint::new_builder()
            .tx_hash(dckb_tx_hash.pack())
            .index(0u32.pack())
            .build();
        let dao_lock_out_point = OutPoint::new_builder()
            .tx_hash(dao_lock_tx_hash.pack())
            .index(0u32.pack())
            .build();
        let custodian_lock_out_point = OutPoint::new_builder()
            .tx_hash(custodian_lock_tx_hash.pack())
            .index(0u32.pack())
            .build();
        let mut dckb_code_hash = [0u8; 32];
        hex_decode(
            b"56721af2c8389a1582a0a32e6c2fe7429101acd13b861e7fbdf06a031c193de3",
            &mut dckb_code_hash,
        )
        .expect("dehex");
        let mut dao_lock_code_hash = [0u8; 32];
        hex_decode(
            b"c485df2bf8ee48cba1af806a657bf4bdc28fe3b6fe9fc8c13502e7af0a96c59b",
            &mut dao_lock_code_hash,
        )
        .expect("dehex");
        let mut custodian_lock_code_hash = [0u8; 32];
        hex_decode(
            b"10c653a5cf01334a9339937751ec6d4fb4549f720b3456ebc58c91a76d4d76da",
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
