use protocol::tex::*;

const TEX_SIDE_SELL_HACP: &str = "sell_hacp";
const TEX_SIDE_BUY_HACP: &str = "buy_hacp";
const TEX_MAX_BLOCK_HEIGHT: u64 = (1_u64 << 40) - 1;

#[wasm_bindgen(getter_with_clone, inspectable)]
pub struct TexActionResult {
    pub signed_action_hex: String,
    pub sign_hash: String,
    pub address: String,
    pub side: String,
    pub serial: u64,
    pub texauth_serial: u64,
    pub price_mei_per_hacp: u64,
    pub lot_hacp: u64,
    pub total_hacp: u64,
    pub maker_balance_at_signing: u64,
    pub spend_floor: u64,
    pub hacp_amount: u64,
    pub hac_mei_net: u64,
    pub taker_fee_mei: u64,
    pub expire_height: u64,
    pub chain_id: u32,
}

#[wasm_bindgen(getter_with_clone, inspectable)]
pub struct TexOrderResult {
    pub address: String,
    pub side: String,
    pub serial: u64,
    pub texauth_serial: u64,
    pub price_mei_per_hacp: u64,
    pub total_hacp: u64,
    pub maker_balance_at_signing: u64,
    pub expire_height: u64,
    pub chain_id: u32,
    pub denominations: String,
    pub bundles_json: String,
}

struct TexOrderBundle {
    denom: u64,
    signed_action_hex: String,
    sign_hash: String,
    spend_floor: u64,
}

fn tex_fold(value: u64, label: &str) -> Ret<Fold64> {
    Fold64::from(value).map_err(|e| format!("{} invalid: {}", label, e))
}

fn tex_asset(serial: u64, amount: u64) -> Ret<AssetAmt> {
    AssetAmt::from(serial, amount)
}

fn tex_trade_mei(price_mei_per_hacp: u64, hacp_amount: u64) -> Ret<u64> {
    price_mei_per_hacp
        .checked_mul(hacp_amount)
        .ok_or_else(|| "trade HAC amount overflow".to_string())
}

// Comisión por lado sobre una pata de HAC, redondeada al alza (E-8).
// fee_bps en puntos básicos: 25 = 0,25%. Debe coincidir byte a byte con el backend.
fn tex_fee_mei(hac_mei: u64, fee_bps: u32) -> u64 {
    if fee_bps == 0 {
        return 0;
    }
    ((hac_mei as u128 * fee_bps as u128 + 9_999) / 10_000) as u64
}

fn tex_order_spend_floor(
    side: &str,
    price_mei_per_hacp: u64,
    lot_hacp: u64,
    total_hacp: u64,
    maker_balance_at_signing: u64,
    fee_bps: u32,
) -> Ret<(u64, u64)> {
    // En SELL el maker gasta HACP (la pata de HAC es lo que cobra, con fee restado → no
    // afecta al suelo de HACP). En BUY el maker gasta HAC e incluye su fee por lado.
    let lot_spend = if side == TEX_SIDE_SELL_HACP {
        lot_hacp
    } else {
        let lot_mei = tex_trade_mei(price_mei_per_hacp, lot_hacp)?;
        lot_mei
            .checked_add(tex_fee_mei(lot_mei, fee_bps))
            .ok_or_else(|| "lot spend overflow".to_string())?
    };
    let total_spend = if side == TEX_SIDE_SELL_HACP {
        total_hacp
    } else {
        let total_mei = tex_trade_mei(price_mei_per_hacp, total_hacp)?;
        total_mei
            .checked_add(tex_fee_mei(total_mei, fee_bps))
            .ok_or_else(|| "total spend overflow".to_string())?
    };
    if maker_balance_at_signing < total_spend {
        return errf!("maker balance at signing is below the declared order total");
    }
    let floor = maker_balance_at_signing
        .checked_sub(total_spend)
        .and_then(|remaining| remaining.checked_add(lot_spend))
        .ok_or_else(|| "order spend floor overflow".to_string())?;
    Ok((lot_spend, floor))
}

fn tex_denominations(raw: &str, total_hacp: u64) -> Ret<Vec<u64>> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let denom = item
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid TEX denomination: {}", item.trim()))?;
        if denom > 0 && denom <= total_hacp && !out.contains(&denom) {
            out.push(denom);
        }
    }
    out.sort_unstable_by(|a, b| b.cmp(a));
    if out.is_empty() || !out.contains(&1) {
        return errf!("denominations must include 1 and at least one value <= total_hacp");
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn create_tex_order_bundle(
    acc: &SysAccount,
    side: &str,
    serial: u64,
    texauth_serial: u64,
    price_mei_per_hacp: u64,
    denom: u64,
    total_hacp: u64,
    maker_balance_at_signing: u64,
    expire_height: u64,
    chain_id: u32,
    fee_bps: u32,
) -> Ret<TexOrderBundle> {
    let lot_mei = tex_trade_mei(price_mei_per_hacp, denom)?;
    let lot_fee = tex_fee_mei(lot_mei, fee_bps);
    let (_, spend_floor) = tex_order_spend_floor(
        side,
        price_mei_per_hacp,
        denom,
        total_hacp,
        maker_balance_at_signing,
        fee_bps,
    )?;
    let mut act = TexCellAct::create_by(Address::from(*acc.address()));
    act.add_cell(Box::new(CellCondHeightAtMost::new(expire_height)))?;
    act.add_cell(Box::new(CellCondChainIdEq::new(chain_id)))?;
    // TEXAUTH is lent by the exchange immediately before this bundle runs.
    // A copied standalone bundle therefore fails before it can move trade funds.
    act.add_cell(Box::new(CellTrsAssetPay::new(tex_asset(
        texauth_serial,
        1,
    )?)))?;
    if side == TEX_SIDE_SELL_HACP {
        // Maker recauda HAC → paga su lado: cobra lot_mei − fee.
        let maker_get = lot_mei
            .checked_sub(lot_fee)
            .ok_or_else(|| "denomination fee exceeds lot".to_string())?;
        act.add_cell(Box::new(CellCondAssetAtLeast::new(tex_asset(
            serial,
            spend_floor,
        )?)))?;
        act.add_cell(Box::new(CellTrsAssetPay::new(tex_asset(serial, denom)?)))?;
        act.add_cell(Box::new(CellTrsZhuGet::new(tex_fold(
            maker_get,
            "denomination HAC",
        )?)))?;
    } else {
        // Maker paga HAC → paga su lado: paga lot_mei + fee.
        let maker_pay = lot_mei
            .checked_add(lot_fee)
            .ok_or_else(|| "denomination HAC overflow".to_string())?;
        act.add_cell(Box::new(CellCondZhuAtLeast::new(tex_fold(
            spend_floor,
            "HAC spend floor",
        )?)))?;
        act.add_cell(Box::new(CellTrsZhuPay::new(tex_fold(
            maker_pay,
            "denomination HAC",
        )?)))?;
        act.add_cell(Box::new(CellTrsAssetGet::new(tex_asset(serial, denom)?)))?;
    }
    let hash = tex_sign_hash(&act);
    act.do_sign(acc)
        .map_err(|e| format!("TEX sign failed: {}", e))?;
    Ok(TexOrderBundle {
        denom,
        signed_action_hex: act.serialize().to_hex(),
        sign_hash: hash.to_hex(),
        spend_floor,
    })
}

fn tex_sign_hash(act: &TexCellAct) -> Hash {
    let mut stuff = Vec::with_capacity(act.addr.size() + act.cells.size());
    act.addr.serialize_to(&mut stuff);
    act.cells.serialize_to(&mut stuff);
    Hash::from(sha3(&stuff))
}

#[allow(clippy::too_many_arguments)]
fn finish_tex_action(
    mut act: TexCellAct,
    acc: &SysAccount,
    side: &str,
    serial: u64,
    texauth_serial: u64,
    price_mei_per_hacp: u64,
    lot_hacp: u64,
    total_hacp: u64,
    maker_balance_at_signing: u64,
    spend_floor: u64,
    hacp_amount: u64,
    hac_mei_net: u64,
    taker_fee_mei: u64,
    expire_height: u64,
    chain_id: u32,
) -> Ret<TexActionResult> {
    let hash = tex_sign_hash(&act);
    if let Err(e) = act.do_sign(acc) {
        return errf!("TEX sign failed: {}", e);
    }
    Ok(TexActionResult {
        signed_action_hex: act.serialize().to_hex(),
        sign_hash: hash.to_hex(),
        address: Address::from(*acc.address()).to_readable(),
        side: side.to_owned(),
        serial,
        texauth_serial,
        price_mei_per_hacp,
        lot_hacp,
        total_hacp,
        maker_balance_at_signing,
        spend_floor,
        hacp_amount,
        hac_mei_net,
        taker_fee_mei,
        expire_height,
        chain_id,
    })
}

#[wasm_bindgen]
pub fn create_tex_order(
    prikey: &str,
    side: &str,
    serial: u64,
    texauth_serial: u64,
    price_mei_per_hacp: u64,
    total_hacp: u64,
    maker_balance_at_signing: u64,
    denominations_csv: &str,
    expire_height: u64,
    chain_id: u32,
    fee_bps: u32,
) -> Ret<TexOrderResult> {
    let acc = q_acc!(prikey);
    let side = side.trim().to_ascii_lowercase();
    if side != TEX_SIDE_SELL_HACP && side != TEX_SIDE_BUY_HACP {
        return errf!("side must be sell_hacp or buy_hacp");
    }
    if serial == 0 || texauth_serial == 0 || price_mei_per_hacp == 0 || total_hacp == 0 {
        return errf!("serial, TEXAUTH serial, price and total must be positive");
    }
    if serial == texauth_serial {
        return errf!("TEXAUTH serial must differ from the traded asset serial");
    }
    if expire_height == 0 {
        return errf!("expire_height is required");
    }

    let denominations = tex_denominations(denominations_csv, total_hacp)?;
    let mut bundles = Vec::with_capacity(denominations.len());
    for denom in denominations {
        bundles.push(create_tex_order_bundle(
            &acc,
            &side,
            serial,
            texauth_serial,
            price_mei_per_hacp,
            denom,
            total_hacp,
            maker_balance_at_signing,
            expire_height,
            chain_id,
            fee_bps,
        )?);
    }
    let denominations = bundles
        .iter()
        .map(|bundle| bundle.denom.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let bundles_json = format!(
        "[{}]",
        bundles
            .iter()
            .map(|bundle| format!(
                "{{\"denom\":\"{}\",\"signedActionHex\":\"{}\",\"signHash\":\"{}\",\"spendFloor\":\"{}\"}}",
                bundle.denom, bundle.signed_action_hex, bundle.sign_hash, bundle.spend_floor
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(TexOrderResult {
        address: Address::from(*acc.address()).to_readable(),
        side,
        serial,
        texauth_serial,
        price_mei_per_hacp,
        total_hacp,
        maker_balance_at_signing,
        expire_height,
        chain_id,
        denominations,
        bundles_json,
    })
}

#[wasm_bindgen]
pub fn create_tex_take(
    prikey: &str,
    order_side: &str,
    order_id: u64,
    take_nonce: u64,
    serial: u64,
    texauth_serial: u64,
    price_mei_per_hacp: u64,
    hacp_amount: u64,
    fee_bps: u32,
    expire_height: u64,
    chain_id: u32,
) -> Ret<TexActionResult> {
    let acc = q_acc!(prikey);
    let order_side = order_side.trim().to_ascii_lowercase();
    if order_side != TEX_SIDE_SELL_HACP && order_side != TEX_SIDE_BUY_HACP {
        return errf!("order_side must be sell_hacp or buy_hacp");
    }
    if order_id == 0
        || take_nonce == 0
        || serial == 0
        || texauth_serial == 0
        || price_mei_per_hacp == 0
        || hacp_amount == 0
    {
        return errf!(
            "order id, take nonce, serial, TEXAUTH serial, price and amount must be positive"
        );
    }
    if serial == texauth_serial {
        return errf!("TEXAUTH serial must differ from the traded asset serial");
    }
    // Bind the deterministic taker signature to one backend order without
    // changing its effective expiry. The first condition remains stricter;
    // this redundant upper bound only carries the replay-domain marker.
    let replay_marker_height = expire_height
        .checked_add(order_id)
        .ok_or_else(|| "TEX take replay marker overflow".to_string())?;
    let nonce_marker_height = expire_height
        .checked_add(take_nonce)
        .ok_or_else(|| "TEX take nonce marker overflow".to_string())?;
    if expire_height > TEX_MAX_BLOCK_HEIGHT
        || replay_marker_height > TEX_MAX_BLOCK_HEIGHT
        || nonce_marker_height > TEX_MAX_BLOCK_HEIGHT
    {
        return errf!("TEX take replay markers exceed the 40-bit block height limit");
    }
    let trade_mei = tex_trade_mei(price_mei_per_hacp, hacp_amount)?;
    let taker_fee_mei = tex_fee_mei(trade_mei, fee_bps);
    let taker_side = if order_side == TEX_SIDE_SELL_HACP {
        TEX_SIDE_BUY_HACP
    } else {
        TEX_SIDE_SELL_HACP
    };
    let mut act = TexCellAct::create_by(Address::from(*acc.address()));
    act.add_cell(Box::new(CellCondHeightAtMost::new(expire_height)))?;
    act.add_cell(Box::new(CellCondHeightAtMost::new(replay_marker_height)))?;
    act.add_cell(Box::new(CellCondHeightAtMost::new(nonce_marker_height)))?;
    act.add_cell(Box::new(CellCondChainIdEq::new(chain_id)))?;
    act.add_cell(Box::new(CellTrsAssetPay::new(tex_asset(
        texauth_serial,
        1,
    )?)))?;
    if order_side == TEX_SIDE_SELL_HACP {
        let pay_mei = trade_mei
            .checked_add(taker_fee_mei)
            .ok_or_else(|| "taker HAC amount overflow".to_string())?;
        act.add_cell(Box::new(CellTrsZhuPay::new(tex_fold(
            pay_mei,
            "taker HAC",
        )?)))?;
        act.add_cell(Box::new(CellTrsAssetGet::new(tex_asset(
            serial,
            hacp_amount,
        )?)))?;
    } else {
        let receive_mei = trade_mei
            .checked_sub(taker_fee_mei)
            .ok_or_else(|| "trade amount must exceed the fixed taker fee".to_string())?;
        act.add_cell(Box::new(CellTrsAssetPay::new(tex_asset(
            serial,
            hacp_amount,
        )?)))?;
        act.add_cell(Box::new(CellTrsZhuGet::new(tex_fold(
            receive_mei,
            "taker HAC",
        )?)))?;
    }
    finish_tex_action(
        act,
        &acc,
        taker_side,
        serial,
        texauth_serial,
        price_mei_per_hacp,
        hacp_amount,
        hacp_amount,
        0,
        0,
        hacp_amount,
        trade_mei,
        taker_fee_mei,
        expire_height,
        chain_id,
    )
}

#[cfg(test)]
mod tex_sdk_tests {
    use super::*;
    use basis::method::verify_signature;

    #[test]
    fn tex_order_roundtrip_is_canonical_and_signed() {
        let acc = SysAccount::create_by_password("sdk_tex_maker").unwrap();
        let bundle = create_tex_order_bundle(
            &acc,
            "sell_hacp",
            1025,
            1026,
            300_000_000,
            10,
            100,
            500,
            765_900,
            0,
            25,
        )
        .unwrap();
        let bytes = hex::decode(&bundle.signed_action_hex).unwrap();
        let (act, used) = TexCellAct::create(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(act.serialize(), bytes);
        assert_eq!(
            act.addr.to_readable(),
            Address::from(*acc.address()).to_readable()
        );
        assert_eq!(act.cells.length(), 6);
        let hash = tex_sign_hash(&act);
        assert_eq!(hash.to_hex(), bundle.sign_hash);
        assert!(verify_signature(&hash, &act.addr, &act.sign));
        assert_eq!(bundle.spend_floor, 410);

        let out = create_tex_order(
            "sdk_tex_maker",
            "sell_hacp",
            1025,
            1026,
            300_000_000,
            100,
            500,
            "1,2,5,10,20,50,100,500,1000",
            765_900,
            0,
            25,
        )
        .unwrap();
        assert_eq!(out.denominations, "100,50,20,10,5,2,1");
        assert!(out.bundles_json.contains("\"denom\":\"1\""));
        assert!(out.bundles_json.contains("\"denom\":\"100\""));
    }

    #[test]
    fn tex_order_floor_allows_only_the_declared_net_drawdown() {
        let (sell_lot, sell_floor) =
            tex_order_spend_floor(TEX_SIDE_SELL_HACP, 300_000_000, 10, 100, 500, 25).unwrap();
        let mut sell_balance = 500;
        let mut sell_runs = 0;
        while sell_balance >= sell_floor {
            sell_balance -= sell_lot;
            sell_runs += 1;
        }
        assert_eq!(sell_runs, 10);
        assert_eq!(sell_balance, 400);

        let (buy_lot, buy_floor) =
            tex_order_spend_floor(TEX_SIDE_BUY_HACP, 300_000_000, 10, 100, 40_000_000_000, 25)
                .unwrap();
        // lot = 3e9 + 0,25% = 3_007_500_000 ; floor = 40e9 − (30e9+0,25%) + lot.
        assert_eq!(buy_lot, 3_007_500_000);
        assert_eq!(buy_floor, 12_932_500_000);
        let mut buy_balance = 40_000_000_000;
        let mut buy_runs = 0;
        while buy_balance >= buy_floor {
            buy_balance -= buy_lot;
            buy_runs += 1;
        }
        assert_eq!(buy_runs, 10);
        assert_eq!(buy_balance, 9_925_000_000);
    }

    #[test]
    fn tex_take_fee_is_part_of_signed_payload() {
        let with_fee = create_tex_take(
            "sdk_tex_taker",
            "sell_hacp",
            41,
            9001,
            1025,
            1026,
            300_000_000,
            10,
            25,
            765_900,
            0,
        )
        .unwrap();
        let no_fee = create_tex_take(
            "sdk_tex_taker",
            "sell_hacp",
            41,
            9001,
            1025,
            1026,
            300_000_000,
            10,
            0,
            765_900,
            0,
        )
        .unwrap();
        assert_ne!(with_fee.sign_hash, no_fee.sign_hash);
        assert_ne!(with_fee.signed_action_hex, no_fee.signed_action_hex);
    }

    #[test]
    fn tex_take_signature_is_bound_to_order_id() {
        let first = create_tex_take(
            "sdk_tex_taker",
            "sell_hacp",
            41,
            9001,
            1025,
            1026,
            300_000_000,
            10,
            25,
            765_900,
            0,
        )
        .unwrap();
        let second = create_tex_take(
            "sdk_tex_taker",
            "sell_hacp",
            42,
            9001,
            1025,
            1026,
            300_000_000,
            10,
            25,
            765_900,
            0,
        )
        .unwrap();
        assert_ne!(first.sign_hash, second.sign_hash);
        assert_ne!(first.signed_action_hex, second.signed_action_hex);
    }

    #[test]
    fn tex_take_signature_is_unique_per_nonce() {
        let first = create_tex_take(
            "sdk_tex_taker",
            "sell_hacp",
            41,
            9001,
            1025,
            1026,
            300_000_000,
            10,
            25,
            765_900,
            0,
        )
        .unwrap();
        let second = create_tex_take(
            "sdk_tex_taker",
            "sell_hacp",
            41,
            9002,
            1025,
            1026,
            300_000_000,
            10,
            25,
            765_900,
            0,
        )
        .unwrap();
        assert_ne!(first.sign_hash, second.sign_hash);
        assert_ne!(first.signed_action_hex, second.signed_action_hex);
    }

    #[test]
    fn tex_take_rejects_replay_marker_above_block_height_width() {
        let result = create_tex_take(
            "sdk_tex_taker",
            "sell_hacp",
            41,
            (1_u64 << 40) - 765_900,
            1025,
            1026,
            300_000_000,
            10,
            25,
            765_900,
            0,
        );
        assert!(result.is_err());
    }
}
