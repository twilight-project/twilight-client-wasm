use crate::*;
use uuid::Uuid;
use wasm_bindgen::prelude::*;

use twilight_client_sdk::programcontroller::ContractManager;
use zkschnorr::Signature as SchnorrSignature;

// create Trader order Output for Memo
//
#[wasm_bindgen(js_name = createTraderOrderOutputMemo)]
pub fn create_trader_order_output_memo(
    script_address: String, // Hex address string
    owner_address: String,  // Hex address string
    balance: u64,
    position_size: u64,
    leverage: u64,
    entry_price: u64,
    order_side: String,
    timebounds: u32,
    scalar: String, // Hex string of Scalar
) -> Result<String, JsValue> {
    // recreate scalar bytes from hex string
    let scalar = match crate::scalar_from_hex(scalar) {
        Ok(scalar) => scalar,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    // convert order side to enum
    let order_side = match twilight_client_sdk::relayer_types::PositionType::from_str(&order_side) {
        Some(order_side) => order_side,
        None => return Err(JsValue::from_str("Invalid OrderSide")),
    };
    // create memo output
    let memo = twilight_client_sdk::util::create_output_memo_for_trader(
        script_address,
        owner_address,
        balance,
        position_size,
        leverage,
        entry_price,
        order_side,
        scalar,
        timebounds,
    );

    match serde_json::to_string(&memo) {
        Ok(j) => Ok(j),
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    }
}

/// create input coin type from output coin
#[wasm_bindgen(js_name = createInputCoinFromOutput)]
pub fn create_input_coin_from_output(output: String, utxo: String) -> Result<String, JsValue> {
    let out: Output = match serde_json::from_str(&output) {
        Ok(out) => out,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let utxo: Utxo = match serde_json::from_str(&utxo) {
        Ok(utxo) => utxo,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let mut inp: Input;
    match out.out_type {
        IOType::Coin => {
            let out_coin = match out.output.get_output_coin() {
                Some(out_coin) => out_coin,
                None => return Err(JsValue::from_str("CoinOutput is not present")),
            };
            inp = Input::coin(InputData::coin(utxo, out_coin.clone(), 0));
        }
        _ => return Err(JsValue::from_str("Not a CoinOutput")),
    }
    match serde_json::to_string(&inp) {
        Ok(str) => Ok(str),
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    }
}
/// create input Memo type from output Memo
#[wasm_bindgen(js_name = createInputMemoFromOutput)]
pub fn create_input_memo_from_output(
    output: String,
    utxo: String,
    amount: u64,
) -> Result<String, JsValue> {
    let out: Output = match serde_json::from_str(&output) {
        Ok(out) => out,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let utxo: Utxo = match serde_json::from_str(&utxo) {
        Ok(utxo) => utxo,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let mut inp: Input;
    match out.out_type {
        IOType::Memo => {
            let out_memo = match out.output.get_output_memo() {
                Some(out_memo) => out_memo,
                None => return Err(JsValue::from_str("MemoOutput is not present")),
            };
            inp = Input::memo(InputData::memo(
                utxo,
                out_memo.clone(),
                0,
                Some(zkvm::Commitment::blinded(amount)),
            ));
        }
        _ => return Err(JsValue::from_str("Not a MemoOutput")),
    }
    match serde_json::to_string(&inp) {
        Ok(str) => Ok(str),
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    }
}

///Sign a msg using private key and public key
/// Returns signature as string
/// msg is the cancel message request
#[wasm_bindgen(js_name = signMessagePk)]
pub fn sign_message_by_pk(msg: String, pk: String, seed: &str) -> Result<String, JsValue> {
    //let msg: String = serde_json::from_str(&msg).unwrap();
    let pk: RistrettoPublicKey = serde_json::from_str(&pk).unwrap();

    //derive private key
    let secret_key: RistrettoSecretKey = crate::hex_str_to_secret_key(seed);
    let message = bincode::serialize(&msg).unwrap();

    let signature: SchnorrSignature =
        pk.sign_msg(&message, &secret_key, ("PublicKeySign").as_bytes());

    // let sig = sign(&msg.as_bytes(), &pk, &sk);
    let j = serde_json::to_string(&signature);
    let msg_to_return = j.unwrap();
    Ok(msg_to_return)
}

///Create a ZkosCreateTraderOrder from ZkosAccount
///
#[wasm_bindgen(js_name = createZkOSTraderOrder)]
pub fn create_trader_order_zkos(
    input_coin: String,
    contract_manager: String, // ContractManager Json String
    seed: &str,
    rscalar: String, // Scalar to encrypt values in memo
    value: u64,
    position_type: String,
    order_type: String,
    leverage: f64,
    entryprice: f64, // entry price of the position. Required in case of LIMIT order
    timebounds: u32,
) -> Result<String, JsValue> {
    //prepare data for signature and same value proof
    //derive private key
    let secret_key: RistrettoSecretKey = crate::hex_str_to_secret_key(seed);
    // unwrap input
    let input: Input = match serde_json::from_str(&input_coin) {
        Ok(inp) => inp,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    // unwrap contract manager
    let program_manager: ContractManager = match serde_json::from_str(&contract_manager) {
        Ok(contract) => contract,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    // decode scalar
    let scalar = match twilight_client_sdk::util::hex_to_scalar(rscalar.clone()) {
        Some(scalar) => scalar,
        None => return Err(JsValue::from_str("Error decoding scalar")),
    };

    let position_size = value * leverage as u64 * entryprice as u64;
    let position_value = value * leverage as u64;
    let order_side =
        match twilight_client_sdk::relayer_types::PositionType::from_str(&position_type) {
            Some(position_type) => position_type,
            None => return Err(JsValue::from_str("Invalid PositionType")),
        };

    let order_status: String = "PENDING".to_string();
    // call create_trader_order_zkos from client wallet lib
    let order_string = twilight_client_sdk::relayer::create_trader_order_zkos(
        input,
        secret_key,
        scalar,
        value,
        position_type,
        order_type,
        leverage,
        value as f64, // Initial margin is the same amount as value locked in input coin
        value as f64, // is same as initial margin
        order_status, //
        entryprice,
        entryprice, // random value. will be updated by relayer later
        position_value,
        position_size,
        order_side,
        &program_manager,
        timebounds,
    )?;
    //let order_string = "order_string".to_string();
    Ok(order_string)
}

/// ExecuteOrderZkos. Used to settle trade or lend orders
/// output_memo = Memo Json String
/// seed  = private signature to derive secret key
/// rest of the normal settle order message
/// tx_type = "ORDERTX" for settling trader orders
/// tx_type = "LENDTX" for settling lend orders
///
#[wasm_bindgen(js_name = executeTradeLendOrderZkOS)]
pub fn execute_trade_lend_order_zkos(
    output_memo: String, //hex string
    seed: &str,
    account_id: String,
    uid: String, // uuid string
    order_type: String,
    order_status: String,
    execution_price_poolshare_price: f64,
    tx_type: String,
) -> Result<String, JsValue> {
    //derive private key
    let secret_key: RistrettoSecretKey = crate::hex_str_to_secret_key(seed);
    //recreate uuid from string
    let uid: Uuid = match Uuid::parse_str(&uid) {
        Ok(uid) => uid,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    // extract Output from hex string
    // Provide the Prover view of the output Memo
    // Input memo will be created by the exchange on behalf of the user
    let memo_bytes = match hex::decode(output_memo.clone()) {
        Ok(memo_bytes) => memo_bytes,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let memo_out: Output = match bincode::deserialize(&memo_bytes) {
        Ok(memo_out) => memo_out,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    // recreate TXTYPE from string
    let tx_type = match twilight_client_sdk::relayer_types::TXType::from_str(&tx_type) {
        Some(tx_type) => tx_type,
        None => return Err(JsValue::from_str("Invalid TxType")),
    };
    // // call execute_order_zkos from client-wallet-lib
    let execute_order = twilight_client_sdk::relayer::execute_order_zkos(
        memo_out,
        &secret_key,
        account_id,
        uid,
        order_type,
        0f64,
        order_status,
        execution_price_poolshare_price,
        tx_type,
    );
    //  let execute_order = "execute_order".to_string();
    Ok(execute_order)
}

/// Create a ZkosLendOrder from ZkosAccount
///
#[wasm_bindgen(js_name = createZkOSLendOrder)]
pub fn create_lend_order_zkos(
    input_coin: String,
    seed: &str,
    contract_address: String, // Hex address string of the script
    rscalar: String,          // Hex string of Scalar
    deposit: u64,
) -> Result<String, JsValue> {
    //derive private key
    let secret_key: RistrettoSecretKey = crate::hex_str_to_secret_key(seed);
    // unwrap input and output from Json
    let input: Input = match serde_json::from_str(&input_coin) {
        Ok(inp) => inp,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    // decode scalar
    let scalar = match twilight_client_sdk::util::hex_to_scalar(rscalar.clone()) {
        Some(scalar) => scalar,
        None => return Err(JsValue::from_str("Error decoding scalar")),
    };
    // extract owner address from input
    let owner_address = match input.as_owner_address() {
        Some(owner_address) => owner_address.clone(),
        None => return Err(JsValue::from_str("Error extracting owner address")),
    };
    let pool_share = 0u64;
    // create output Memo for Lender
    let output = twilight_client_sdk::util::create_output_memo_for_lender(
        contract_address,
        owner_address.clone(),
        deposit,
        pool_share,
        scalar,
        0u32,
    );
    // call create_lend_order_zkos from client-wallet-lib
    let lend_order = twilight_client_sdk::relayer::create_lend_order_zkos(
        input,
        output,
        secret_key,
        rscalar,
        deposit,
        owner_address,
        deposit as f64,
        "LEND".to_string(),
        "PENDING".to_string(),
        deposit as f64,
    )?;
    // let lend_order = "lend_order".to_string();
    Ok(lend_order)
}

/// CancelTraderOrderZkos
///
#[wasm_bindgen(js_name = cancelTraderOrderZkOS)]
pub fn cancel_trader_order_zkos(
    add_hex: String, //hex address string
    seed: &str,
    uuid: String,
) -> Result<String, JsValue> {
    //derive private key
    let secret_key: RistrettoSecretKey = crate::hex_str_to_secret_key(seed);

    //recreate uuid
    let uuid: Uuid = match serde_json::from_str(&uuid) {
        Ok(uid) => uid,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };

    // call cancel_trader_order_zkos from client-wallet-lib
    let cancel_order = twilight_client_sdk::relayer::cancel_trader_order_zkos(
        add_hex.clone(),
        &secret_key,
        add_hex.clone(),
        uuid,
        "LIMIT".to_string(),
        "PENDING".to_string(),
    );
    //  let cancel_order = "cancel_order".to_string();
    Ok(cancel_order)
}

/// QueryTraderOrderZkos
///
#[wasm_bindgen(js_name = queryTraderOrderZkos)]
pub fn query_trader_order_zkos(
    add_hex: String, //hex address string
    seed: &str,
    order_status: String,
) -> Result<String, JsValue> {
    //derive private key
    let secret_key: RistrettoSecretKey = crate::hex_str_to_secret_key(seed);
    let querry_trader_order = twilight_client_sdk::relayer::query_trader_order_zkos(
        add_hex.clone(),
        &secret_key,
        add_hex,
        order_status,
    );
    //   let querry_trader_order = "querry_trader_order".to_string();
    Ok(querry_trader_order)
}

/// QueryLendOrderZkos
///
#[wasm_bindgen(js_name = queryLendOrderZkos)]
pub fn query_lend_order_zkos(
    add_hex: String, //hex address string
    seed: &str,
    order_status: String,
) -> Result<String, JsValue> {
    //derive private key
    let secret_key: RistrettoSecretKey = crate::hex_str_to_secret_key(seed);
    let querry_lend_order = twilight_client_sdk::relayer::query_lend_order_zkos(
        add_hex.clone(),
        &secret_key,
        add_hex,
        order_status,
    );
    // let querry_lend_order = "querry_lend_order".to_string();
    Ok(querry_lend_order)
}
