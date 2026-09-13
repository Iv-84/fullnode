//! TEX order/take action preparation for Unified SDK 2.0.
//!
//! These helpers build the exact kind-22 wire payload and its embedded-signature
//! digest. They deliberately accept an address, never a private key; the wallet
//! vault signs the digest and `tex.attach_signature` verifies and attaches it.

use base::BinaryCodecs;
use field::{Address, BlockHeight, Decode, Encode, Fold64, Uint1, Uint2, Uint4};

use crate::error::{SdkError, SdkErrorCode};
use crate::json::{SdkJsonTo, arr, kv, obj, q, qnum};

const TEX_ACTION_KIND: u16 = 22;
const TEX_SIDE_SELL_HACP: &str = "sell_hacp";
const TEX_SIDE_BUY_HACP: &str = "buy_hacp";
const TEX_MAX_BLOCK_HEIGHT: u64 = (1_u64 << 40) - 1;
const TEX_SIGN_SIZE: usize = 33 + 64;

#[derive(Debug, Clone, PartialEq)]
pub struct TexPreparedAction {
    pub action_hex: String,
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

#[derive(Debug, Clone, PartialEq)]
pub struct TexOrderBundle {
    pub denomination: u64,
    pub action_hex: String,
    pub sign_hash: String,
    pub spend_floor: u64,
}

#[derive(Debug, Clone, PartialEq)]
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
    pub denominations: Vec<u64>,
    pub bundles: Vec<TexOrderBundle>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TexSignedAction {
    pub signed_action_hex: String,
    pub sign_hash: String,
    pub address: String,
}

impl SdkJsonTo for TexPreparedAction {
    fn to_json_string(&self) -> String {
        obj(vec![
            kv("schema", q("tex-prepared-action@1")),
            kv("action_hex", q(&self.action_hex)),
            kv("sign_hash", q(&self.sign_hash)),
            kv("address", q(&self.address)),
            kv("side", q(&self.side)),
            kv("serial", qnum(self.serial)),
            kv("texauth_serial", qnum(self.texauth_serial)),
            kv("price_mei_per_hacp", qnum(self.price_mei_per_hacp)),
            kv("lot_hacp", qnum(self.lot_hacp)),
            kv("total_hacp", qnum(self.total_hacp)),
            kv(
                "maker_balance_at_signing",
                qnum(self.maker_balance_at_signing),
            ),
            kv("spend_floor", qnum(self.spend_floor)),
            kv("hacp_amount", qnum(self.hacp_amount)),
            kv("hac_mei_net", qnum(self.hac_mei_net)),
            kv("taker_fee_mei", qnum(self.taker_fee_mei)),
            kv("expire_height", qnum(self.expire_height)),
            kv("chain_id", qnum(self.chain_id)),
        ])
    }
}

impl SdkJsonTo for TexOrderBundle {
    fn to_json_string(&self) -> String {
        obj(vec![
            kv("denomination", qnum(self.denomination)),
            kv("action_hex", q(&self.action_hex)),
            kv("sign_hash", q(&self.sign_hash)),
            kv("spend_floor", qnum(self.spend_floor)),
        ])
    }
}

impl SdkJsonTo for TexOrderResult {
    fn to_json_string(&self) -> String {
        obj(vec![
            kv("schema", q("tex-order@1")),
            kv("address", q(&self.address)),
            kv("side", q(&self.side)),
            kv("serial", qnum(self.serial)),
            kv("texauth_serial", qnum(self.texauth_serial)),
            kv("price_mei_per_hacp", qnum(self.price_mei_per_hacp)),
            kv("total_hacp", qnum(self.total_hacp)),
            kv(
                "maker_balance_at_signing",
                qnum(self.maker_balance_at_signing),
            ),
            kv("expire_height", qnum(self.expire_height)),
            kv("chain_id", qnum(self.chain_id)),
            kv(
                "denominations",
                arr(self.denominations.iter().map(|v| qnum(*v)).collect()),
            ),
            kv(
                "bundles",
                arr(self.bundles.iter().map(SdkJsonTo::to_json_string).collect()),
            ),
        ])
    }
}

impl SdkJsonTo for TexSignedAction {
    fn to_json_string(&self) -> String {
        obj(vec![
            kv("schema", q("tex-signed-action@1")),
            kv("signed_action_hex", q(&self.signed_action_hex)),
            kv("sign_hash", q(&self.sign_hash)),
            kv("address", q(&self.address)),
        ])
    }
}

fn parse_error(message: impl Into<String>) -> SdkError {
    SdkError::new(SdkErrorCode::ParseFailed, message)
}

fn checked_side(raw: &str, label: &str) -> Result<String, SdkError> {
    let side = raw.trim().to_ascii_lowercase();
    if side != TEX_SIDE_SELL_HACP && side != TEX_SIDE_BUY_HACP {
        return Err(parse_error(format!(
            "{label} must be sell_hacp or buy_hacp"
        )));
    }
    Ok(side)
}

fn checked_address(raw: &str) -> Result<Address, SdkError> {
    let address = Address::from_readable(raw)
        .map_err(|e| SdkError::new(SdkErrorCode::InvalidAddress, e.to_string()))?;
    address
        .must_privkey()
        .map_err(|e| SdkError::new(SdkErrorCode::InvalidAddress, e.to_string()))?;
    Ok(address)
}

fn checked_chain_id(value: u64) -> Result<u32, SdkError> {
    value
        .try_into()
        .map_err(|_| parse_error("chain_id exceeds the 32-bit wire limit"))
}

fn checked_fee_bps(value: u64) -> Result<u32, SdkError> {
    value
        .try_into()
        .map_err(|_| parse_error("fee_bps exceeds the 32-bit limit"))
}

fn checked_fold(value: u64, label: &str) -> Result<Fold64, SdkError> {
    Fold64::from(value).map_err(|e| parse_error(format!("{label} invalid: {e}")))
}

fn tex_trade_mei(price_mei_per_hacp: u64, hacp_amount: u64) -> Result<u64, SdkError> {
    price_mei_per_hacp
        .checked_mul(hacp_amount)
        .ok_or_else(|| parse_error("trade HAC amount overflow"))
}

fn tex_fee_mei(hac_mei: u64, fee_bps: u32) -> Result<u64, SdkError> {
    let fee = (hac_mei as u128 * fee_bps as u128 + 9_999) / 10_000;
    fee.try_into()
        .map_err(|_| parse_error("TEX fee exceeds the 64-bit limit"))
}

fn tex_order_spend_floor(
    side: &str,
    price_mei_per_hacp: u64,
    lot_hacp: u64,
    total_hacp: u64,
    maker_balance_at_signing: u64,
    fee_bps: u32,
) -> Result<(u64, u64), SdkError> {
    let lot_spend = if side == TEX_SIDE_SELL_HACP {
        lot_hacp
    } else {
        let lot_mei = tex_trade_mei(price_mei_per_hacp, lot_hacp)?;
        lot_mei
            .checked_add(tex_fee_mei(lot_mei, fee_bps)?)
            .ok_or_else(|| parse_error("lot spend overflow"))?
    };
    let total_spend = if side == TEX_SIDE_SELL_HACP {
        total_hacp
    } else {
        let total_mei = tex_trade_mei(price_mei_per_hacp, total_hacp)?;
        total_mei
            .checked_add(tex_fee_mei(total_mei, fee_bps)?)
            .ok_or_else(|| parse_error("total spend overflow"))?
    };
    if maker_balance_at_signing < total_spend {
        return Err(parse_error(
            "maker balance at signing is below the declared order total",
        ));
    }
    let floor = maker_balance_at_signing
        .checked_sub(total_spend)
        .and_then(|remaining| remaining.checked_add(lot_spend))
        .ok_or_else(|| parse_error("order spend floor overflow"))?;
    Ok((lot_spend, floor))
}

fn tex_denominations(raw: &str, total_hacp: u64) -> Result<Vec<u64>, SdkError> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let text = item.trim();
        let denomination = text
            .parse::<u64>()
            .map_err(|_| parse_error(format!("invalid TEX denomination: {text}")))?;
        if denomination > 0 && denomination <= total_hacp && !out.contains(&denomination) {
            out.push(denomination);
        }
    }
    out.sort_unstable_by(|a, b| b.cmp(a));
    if out.is_empty() || !out.contains(&1) {
        return Err(parse_error(
            "denominations must include 1 and at least one value <= total_hacp",
        ));
    }
    Ok(out)
}

#[derive(Debug)]
enum Cell {
    Fold(u8, u64, &'static str),
    Asset(u8, u64, u64),
    Height(u64),
    Chain(u32),
}

impl Cell {
    fn encode_to(&self, out: &mut Vec<u8>) -> Result<(), SdkError> {
        match *self {
            Self::Fold(id, value, label) => {
                Uint1::from(id).encode_to(out);
                checked_fold(value, label)?.encode_to(out);
            }
            Self::Asset(id, serial, amount) => {
                Uint1::from(id).encode_to(out);
                checked_fold(serial, "asset serial")?.encode_to(out);
                checked_fold(amount, "asset amount")?.encode_to(out);
            }
            Self::Height(height) => {
                let height = BlockHeight::from_checked(height)
                    .ok_or_else(|| parse_error("height exceeds the 40-bit wire limit"))?;
                Uint1::from(23).encode_to(out);
                height.encode_to(out);
            }
            Self::Chain(chain_id) => {
                Uint1::from(25).encode_to(out);
                Uint4::from(chain_id).encode_to(out);
            }
        }
        Ok(())
    }
}

fn build_unsigned_action(address: Address, cells: Vec<Cell>) -> Result<(String, String), SdkError> {
    let cell_count: u8 = cells
        .len()
        .try_into()
        .map_err(|_| parse_error("too many TEX cells"))?;
    let mut wire = Vec::new();
    Uint2::from(TEX_ACTION_KIND).encode_to(&mut wire);
    address.encode_to(&mut wire);
    Uint1::from(cell_count).encode_to(&mut wire);
    for cell in cells {
        cell.encode_to(&mut wire)?;
    }
    wire.resize(wire.len() + TEX_SIGN_SIZE, 0);

    let action = crate::codec::standard_codecs()?
        .decode_action_exact(&wire)
        .map_err(SdkError::from)?;
    if action.kind() != TEX_ACTION_KIND {
        return Err(parse_error("prepared action is not TEX kind 22"));
    }
    let sign_hash = tex_sign_hash(&wire)?;
    Ok((hex::encode(wire), hex::encode(sign_hash)))
}

fn tex_sign_hash(wire: &[u8]) -> Result<[u8; 32], SdkError> {
    let signed_end = wire
        .len()
        .checked_sub(TEX_SIGN_SIZE)
        .filter(|end| *end >= 2 + Address::SIZE + 1)
        .ok_or_else(|| parse_error("TEX action is too short"))?;
    Ok(sys::calculate_hash(&wire[2..signed_end]))
}

fn create_tex_order_bundle(
    address: Address,
    side: &str,
    serial: u64,
    texauth_serial: u64,
    price_mei_per_hacp: u64,
    denomination: u64,
    total_hacp: u64,
    maker_balance_at_signing: u64,
    expire_height: u64,
    chain_id: u32,
    fee_bps: u32,
) -> Result<TexOrderBundle, SdkError> {
    let lot_mei = tex_trade_mei(price_mei_per_hacp, denomination)?;
    let lot_fee = tex_fee_mei(lot_mei, fee_bps)?;
    let (_, spend_floor) = tex_order_spend_floor(
        side,
        price_mei_per_hacp,
        denomination,
        total_hacp,
        maker_balance_at_signing,
        fee_bps,
    )?;
    let mut cells = vec![
        Cell::Height(expire_height),
        Cell::Chain(chain_id),
        Cell::Asset(7, texauth_serial, 1),
    ];
    if side == TEX_SIDE_SELL_HACP {
        let maker_get = lot_mei
            .checked_sub(lot_fee)
            .ok_or_else(|| parse_error("denomination fee exceeds lot"))?;
        cells.extend([
            Cell::Asset(21, serial, spend_floor),
            Cell::Asset(7, serial, denomination),
            Cell::Fold(2, maker_get, "denomination HAC"),
        ]);
    } else {
        let maker_pay = lot_mei
            .checked_add(lot_fee)
            .ok_or_else(|| parse_error("denomination HAC overflow"))?;
        cells.extend([
            Cell::Fold(12, spend_floor, "HAC spend floor"),
            Cell::Fold(1, maker_pay, "denomination HAC"),
            Cell::Asset(8, serial, denomination),
        ]);
    }
    let (action_hex, sign_hash) = build_unsigned_action(address, cells)?;
    Ok(TexOrderBundle {
        denomination,
        action_hex,
        sign_hash,
        spend_floor,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_tex_order(
    address: &str,
    side: &str,
    serial: u64,
    texauth_serial: u64,
    price_mei_per_hacp: u64,
    total_hacp: u64,
    maker_balance_at_signing: u64,
    denominations_csv: &str,
    expire_height: u64,
    chain_id: u64,
    fee_bps: u64,
) -> Result<TexOrderResult, SdkError> {
    let address = checked_address(address)?;
    let side = checked_side(side, "side")?;
    let chain_id = checked_chain_id(chain_id)?;
    let fee_bps = checked_fee_bps(fee_bps)?;
    if serial == 0 || texauth_serial == 0 || price_mei_per_hacp == 0 || total_hacp == 0 {
        return Err(parse_error(
            "serial, TEXAUTH serial, price and total must be positive",
        ));
    }
    if serial == texauth_serial {
        return Err(parse_error(
            "TEXAUTH serial must differ from the traded asset serial",
        ));
    }
    if expire_height == 0 || expire_height > TEX_MAX_BLOCK_HEIGHT {
        return Err(parse_error("expire_height must fit the 40-bit wire limit"));
    }
    let denominations = tex_denominations(denominations_csv, total_hacp)?;
    let mut bundles = Vec::with_capacity(denominations.len());
    for &denomination in &denominations {
        bundles.push(create_tex_order_bundle(
            address,
            &side,
            serial,
            texauth_serial,
            price_mei_per_hacp,
            denomination,
            total_hacp,
            maker_balance_at_signing,
            expire_height,
            chain_id,
            fee_bps,
        )?);
    }
    Ok(TexOrderResult {
        address: address.to_readable(),
        side,
        serial,
        texauth_serial,
        price_mei_per_hacp,
        total_hacp,
        maker_balance_at_signing,
        expire_height,
        chain_id,
        denominations,
        bundles,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create_tex_take(
    address: &str,
    order_side: &str,
    order_id: u64,
    take_nonce: u64,
    serial: u64,
    texauth_serial: u64,
    price_mei_per_hacp: u64,
    hacp_amount: u64,
    fee_bps: u64,
    expire_height: u64,
    chain_id: u64,
) -> Result<TexPreparedAction, SdkError> {
    let address = checked_address(address)?;
    let order_side = checked_side(order_side, "order_side")?;
    let chain_id = checked_chain_id(chain_id)?;
    let fee_bps = checked_fee_bps(fee_bps)?;
    if order_id == 0
        || take_nonce == 0
        || serial == 0
        || texauth_serial == 0
        || price_mei_per_hacp == 0
        || hacp_amount == 0
    {
        return Err(parse_error(
            "order id, take nonce, serial, TEXAUTH serial, price and amount must be positive",
        ));
    }
    if serial == texauth_serial {
        return Err(parse_error(
            "TEXAUTH serial must differ from the traded asset serial",
        ));
    }
    let replay_marker_height = expire_height
        .checked_add(order_id)
        .ok_or_else(|| parse_error("TEX take replay marker overflow"))?;
    let nonce_marker_height = expire_height
        .checked_add(take_nonce)
        .ok_or_else(|| parse_error("TEX take nonce marker overflow"))?;
    if expire_height == 0
        || expire_height > TEX_MAX_BLOCK_HEIGHT
        || replay_marker_height > TEX_MAX_BLOCK_HEIGHT
        || nonce_marker_height > TEX_MAX_BLOCK_HEIGHT
    {
        return Err(parse_error(
            "TEX take replay markers exceed the 40-bit block height limit",
        ));
    }
    let trade_mei = tex_trade_mei(price_mei_per_hacp, hacp_amount)?;
    let taker_fee_mei = tex_fee_mei(trade_mei, fee_bps)?;
    let taker_side = if order_side == TEX_SIDE_SELL_HACP {
        TEX_SIDE_BUY_HACP
    } else {
        TEX_SIDE_SELL_HACP
    };
    let mut cells = vec![
        Cell::Height(expire_height),
        Cell::Height(replay_marker_height),
        Cell::Height(nonce_marker_height),
        Cell::Chain(chain_id),
        Cell::Asset(7, texauth_serial, 1),
    ];
    if order_side == TEX_SIDE_SELL_HACP {
        let pay_mei = trade_mei
            .checked_add(taker_fee_mei)
            .ok_or_else(|| parse_error("taker HAC amount overflow"))?;
        cells.extend([
            Cell::Fold(1, pay_mei, "taker HAC"),
            Cell::Asset(8, serial, hacp_amount),
        ]);
    } else {
        let receive_mei = trade_mei
            .checked_sub(taker_fee_mei)
            .ok_or_else(|| parse_error("trade amount must exceed the taker fee"))?;
        cells.extend([
            Cell::Asset(7, serial, hacp_amount),
            Cell::Fold(2, receive_mei, "taker HAC"),
        ]);
    }
    let (action_hex, sign_hash) = build_unsigned_action(address, cells)?;
    Ok(TexPreparedAction {
        action_hex,
        sign_hash,
        address: address.to_readable(),
        side: taker_side.to_owned(),
        serial,
        texauth_serial,
        price_mei_per_hacp,
        lot_hacp: hacp_amount,
        total_hacp: hacp_amount,
        maker_balance_at_signing: 0,
        spend_floor: 0,
        hacp_amount,
        hac_mei_net: trade_mei,
        taker_fee_mei,
        expire_height,
        chain_id,
    })
}

pub fn attach_tex_signature(
    action_hex: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<TexSignedAction, SdkError> {
    let mut wire = hex::decode(action_hex.trim_start_matches("0x").trim_start_matches("0X"))
        .map_err(|_| parse_error("TEX action hex invalid"))?;
    let action = crate::codec::standard_codecs()?
        .decode_action_exact(&wire)
        .map_err(SdkError::from)?;
    if action.kind() != TEX_ACTION_KIND {
        return Err(parse_error("action is not TEX kind 22"));
    }
    let sign_hash = tex_sign_hash(&wire)?;
    let public_key: [u8; 33] = crate::inspect::decode_hex_fixed(
        public_key_hex,
        SdkErrorCode::InvalidPublicKey,
        "public key must be 33-byte compressed hex",
    )?;
    if !sys::Account::compressed_public_key_valid(&public_key) {
        return Err(SdkError::new(
            SdkErrorCode::InvalidPublicKey,
            "public key is not a valid secp256k1 compressed point",
        ));
    }
    let signature: [u8; 64] = crate::inspect::decode_hex_fixed(
        signature_hex,
        SdkErrorCode::BadSignature,
        "signature must be 64-byte hex",
    )?;
    let address_end = 2 + Address::SIZE;
    let (address, used) = Address::decode(&wire[2..address_end]).map_err(SdkError::from)?;
    if used != Address::SIZE {
        return Err(parse_error("TEX signer address has trailing bytes"));
    }
    let signer_address = Address::from(sys::Account::get_address_by_public_key(public_key));
    if signer_address != address {
        return Err(SdkError::new(
            SdkErrorCode::BadSignature,
            "public key does not match the TEX action address",
        ));
    }
    if !sys::Account::verify_signature(&sign_hash, &public_key, &signature) {
        return Err(SdkError::new(
            SdkErrorCode::BadSignature,
            "TEX action signature verification failed",
        ));
    }
    let sign_offset = wire.len() - TEX_SIGN_SIZE;
    wire[sign_offset..sign_offset + 33].copy_from_slice(&public_key);
    wire[sign_offset + 33..].copy_from_slice(&signature);
    crate::codec::standard_codecs()?
        .decode_action_exact(&wire)
        .map_err(SdkError::from)?;
    Ok(TexSignedAction {
        signed_action_hex: hex::encode(wire),
        sign_hash: hex::encode(sign_hash),
        address: address.to_readable(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_bundle_is_canonical_and_externally_signable() {
        let account = sys::Account::create_by("sdk_tex_maker").unwrap();
        let result = create_tex_order(
            &account.readable(),
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
        assert_eq!(result.denominations, vec![100, 50, 20, 10, 5, 2, 1]);
        assert_eq!(result.bundles[0].spend_floor, 500);
        assert_eq!(result.bundles.last().unwrap().spend_floor, 401);

        let bundle = result.bundles.last().unwrap();
        let digest: [u8; 32] = hex::decode(&bundle.sign_hash).unwrap().try_into().unwrap();
        let signature = account.do_sign(&digest);
        let signed = attach_tex_signature(
            &bundle.action_hex,
            &hex::encode(account.public_key().serialize_compressed()),
            &hex::encode(signature),
        )
        .unwrap();
        assert_eq!(signed.sign_hash, bundle.sign_hash);
        crate::codec::standard_codecs()
            .unwrap()
            .decode_action_exact(&hex::decode(signed.signed_action_hex).unwrap())
            .unwrap();
    }

    #[test]
    fn order_floor_allows_only_declared_drawdown() {
        assert_eq!(
            tex_order_spend_floor(TEX_SIDE_SELL_HACP, 300_000_000, 10, 100, 500, 25).unwrap(),
            (10, 410)
        );
        assert_eq!(
            tex_order_spend_floor(TEX_SIDE_BUY_HACP, 300_000_000, 10, 100, 40_000_000_000, 25,)
                .unwrap(),
            (3_007_500_000, 12_932_500_000)
        );
    }

    #[test]
    fn take_digest_binds_fee_order_and_nonce() {
        let account = sys::Account::create_by("sdk_tex_taker").unwrap();
        let make = |order_id, nonce, fee| {
            create_tex_take(
                &account.readable(),
                "sell_hacp",
                order_id,
                nonce,
                1025,
                1026,
                300_000_000,
                10,
                fee,
                765_900,
                0,
            )
            .unwrap()
            .sign_hash
        };
        assert_ne!(make(41, 9001, 25), make(41, 9001, 0));
        assert_ne!(make(41, 9001, 25), make(42, 9001, 25));
        assert_ne!(make(41, 9001, 25), make(41, 9002, 25));
    }

    #[test]
    fn attach_rejects_wrong_signer() {
        let account = sys::Account::create_by("sdk_tex_taker").unwrap();
        let other = sys::Account::create_by("other").unwrap();
        let action = create_tex_take(
            &account.readable(),
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
        let digest: [u8; 32] = hex::decode(&action.sign_hash).unwrap().try_into().unwrap();
        let error = attach_tex_signature(
            &action.action_hex,
            &hex::encode(other.public_key().serialize_compressed()),
            &hex::encode(other.do_sign(&digest)),
        )
        .unwrap_err();
        assert_eq!(error.code, "bad_signature");
    }
}
