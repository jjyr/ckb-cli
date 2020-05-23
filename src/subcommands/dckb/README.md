# DCKB command

DCKB related operations, this subcommand will migrate to plugin in the future.

## Installation

``` sh
cargo install ckb-cli --git https://github.com/jjyr/ckb-cli.git --branch DCKB
```

## Operations

### Deposit

Deposit CKB to NervosDAO and get DCKB token.

Notice: A block header became mature(referenceable) after four epochs, so after the deposition, we must wait for four epochs to transfer the newly created DCKB.

``` bash
ckb-cli dckb deposit --from-account <address>  --capacity <deposit CKB amount> --tx-fee <fee>
```

### Query DCKB

Query DCKB balance.

``` bash
ckb-cli dckb query-dckb --address <address>

# outputs:
dckb_cells:
  - cell:
      capacity: 11800000000
      data_bytes: 24
      index:
        output_index: 2
        tx_index: 1
      lock_hash: 0x9798d3ccd74bf24b1771774c6e1ff40074dff068683140a93f71a9092e7655d5
      number: 87803
      tx_hash: 0x6f76caaa41afd809acba6e37ac1dbd7a6af9fa8279908ac91d58dbe2b1633f46
      tx_index: 2
      type_hashes:
        - 0x501fd8267f7448eda4f8b1d0245174c7fc163c1b2f149346abc097b319a1c624
        - 0x358945de3ce29d5daba5ea00a5c68f52137e2da578ae0a1d83b145e9b80edf15
    dckb_amount: 131874
    dckb_height: 90263
tip_number: 90263
total_capacity: 11800000000
total_dckb: 131874
```

* `total_dckb` represents current owned DCKB amount(includes NervosDAO compensation counted to the `tip_number`).
* `total_capacity` represents CKB capacity of theses DCKB cells.

> Notice, after deposition, we need to wait for 4 epochs to use the DCKB token. CKB only allows transaction refers to block headers which older than 4 epochs.

### Transfer DCKB

Transfer DCKB.

``` bash
ckb-cli dckb transfer --capacity <DCKB amount> --from-account <sender address> --to-address <receiver address> --tx-fee <fee>
```

### Withdraw NervosDAO

To withdraw CKB from NervosDAO we need destroy corresponded DCKB token.

The withdrawal based on normal NervosDAO, so we keep the same rules; Our withdrawal also separated into two steps.

#### prepare withdraw

In this step, we send a tx to prepare NervosDAO withdraw cell, in the same tx we custodian DCKB corresponded to the original deposited CKB amount.

1. Use query-dao-cells command to query withdrawable DAO cells.

``` bash
ckb-cli dckb query-dao-cells --address <address>
```

2. Send prepare tx.

``` bash
ckb-cli dckb prepare --out-point <dao cell outpoint> --from-account <address> --tx-fee <fee>
```

#### withdraw

In this step, we withdraw CKB from NervosDAO and destroy coresponded DCKB.

1. Query prepared DAO cells.

``` bash
ckb-cli dckb query-prepared-cells --address <address>
```

2. Send withdraw tx.

``` bash
ckb-cli dckb withdraw --out-point <dao cell outpoint> --from-account <address> --tx-fee <fee>
```

If the withdrawal succeeds, we will receive our CKB and NervosDAO compensation.

> Notice, the two withdrawal steps is exactly the NervosDAO withdrawal plus DCKB's logic.
> So we share the same rules:
> 1. Withdraw must be executed in N * 180 epochs after the deposition.
> 2. The withdrawal tx must be sent after 4 epochs since the prepare tx.
>
> DCKB's rules:
> 1. The withdrawal must be completed within 42 epochs(~7 days in the mainnet) since the withdrawal started; otherwise, after 42 epochs anyone can unlock your CKB.
