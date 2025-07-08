pub mod account;
pub mod relayer_ops;
mod test;
pub mod tx;
pub mod zk_account;

use std::convert::From;
//use uuid::Uuid;
use wasm_bindgen::prelude::*;
//use rand::rngs::OsRng;

use crate::zk_account::ZkAccount;
use ::transaction::quisquislib::{
    accounts::Account,
    elgamal::ElGamalCommitment,
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use address::{Address, AddressType, Network};

use console_error_panic_hook;
use core::convert::TryInto;
use curve25519_dalek::scalar::Scalar;
use zkschnorr::Signature;
use zkvm::zkos_types::{
    IOType, Input, InputData, Output, OutputCoin, OutputData, OutputMemo, Utxo,
};

use hex;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::panic;
use web_sys;

//Utility functions defined here
pub fn public_key_to_hex(pk: RistrettoPublicKey) -> String {
    hex::encode(pk.as_bytes())
}
// convert the hex string into a RistrettoPublicKey
pub fn public_key_from_hex(hex_str: String) -> Result<RistrettoPublicKey, &'static str> {
    let bytes = match hex::decode(hex_str) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Error decoding hex string"),
    };
    match RistrettoPublicKey::from_bytes(&bytes) {
        Ok(pk) => Ok(pk),
        Err(_) => Err("Error converting bytes to RistrettoPublicKey"),
    }
}

// convert scalar into hex string
pub fn scalar_to_hex(scalar: Scalar) -> String {
    hex::encode(scalar.to_bytes())
}
// convert hex string into scalar
pub fn scalar_from_hex(hex_str: String) -> Result<Scalar, &'static str> {
    let bytes = match hex::decode(hex_str) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Error decoding hex string"),
    };
    let bytes_32: [u8; 32] = match bytes.try_into() {
        Ok(bytes_32) => bytes_32,
        Err(_) => return Err("Error converting bytes to 32 bytes array"),
    };
    match Scalar::from_canonical_bytes(bytes_32) {
        Some(scalar) => Ok(scalar),
        None => Err("Error converting bytes to Scalar"),
    }
}

//Utility function used for converting seed to Ristretto secret Key
fn hex_str_to_secret_key(seed: &str) -> RistrettoSecretKey {
    //doing hash for more security and restricting size to 32 bytes
    //let mut hasher = Keccak256::new();
    //hasher.update(seed);
    //let hash_32: [u8; 32] = hasher.finalize().try_into().unwrap();
    // NO Need to do Hash here. The SecreetKey::from_bytes function is already doing a 512bit hash internally
    //derive private key
    SecretKey::from_bytes(seed.as_bytes())
}

// Called when the wasm module is instantiated
#[wasm_bindgen(start)]
pub fn main() {
    // Use `web_sys`'s global `window` function to get a handle on the global
    // window object.
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let _body = document.body().expect("document should have a body");
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    //Ok(())
}

#[wasm_bindgen(js_name = generatePublicKeyFromSignature)]
pub fn generate_public_key_from_signature(seed: &str) -> Result<String, JsValue> {
    //derive private key
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);
    let pk = RistrettoPublicKey::from_secret_key(&sk, &mut OsRng);

    Ok(public_key_to_hex(pk))
}

// create random scalar and return as hex string
#[wasm_bindgen(js_name = generateRandomScalar)]
pub fn generate_random_scalar() -> Result<String, JsValue> {
    let random_scalar = Scalar::random(&mut OsRng);
    Ok(scalar_to_hex(random_scalar))
}
///Verify Public/Private Keypair.
/// Returns true iff the public key corresponds to private key
///
#[wasm_bindgen(js_name = verifyKeyPair)]
pub fn verify_keypair(seed: &str, pk: String) -> Result<bool, JsValue> {
    // create sk from seed
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);
    //recreate public key
    let pk = match public_key_from_hex(pk) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(e)),
    };

    if pk.verify_keypair(&sk).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

///Update the Public key with r.
/// Returns Updated public key and r
///
#[wasm_bindgen(js_name = updatePublicKey)]
pub fn update_public_key(key: String, random_scalar: String) -> Result<String, JsValue> {
    // Parse the string of data into a RistrettoPublicKey object.
    let pk = match public_key_from_hex(key) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(e)),
    };

    let random_scalar = match scalar_from_hex(random_scalar) {
        Ok(scalar) => scalar,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    let updated_pk = RistrettoPublicKey::update_public_key(&pk, random_scalar);

    Ok(public_key_to_hex(updated_pk))
}
///Verify Updated Public key.
/// Returns true iff pk * r = upk
///
#[wasm_bindgen(js_name = verifyUpdatePublicKey)]
pub fn verify_update_public_key(pk: String, upk: String, scalar: String) -> Result<bool, JsValue> {
    let pk = match public_key_from_hex(pk) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    let upk = match public_key_from_hex(upk) {
        Ok(upk) => upk,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    let scalar = match scalar_from_hex(scalar) {
        Ok(scalar) => scalar,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    Ok(RistrettoPublicKey::verify_public_key_update(
        &upk, &pk, scalar,
    ))
}

///Generate New Random Address by updating the public key and converting it into a standard address
/// Outputs a HEX address directly
#[wasm_bindgen(js_name = generateNewRandomAddress)]
pub fn generate_random_address(pk: String) -> Result<String, JsValue> {
    // create random scalar r for updating pk
    let random_scalar = Scalar::random(&mut OsRng);
    let r = scalar_to_hex(random_scalar);
    //update public key
    let updated_public_key = update_public_key(pk, r)?;

    let updated_public_key = match public_key_from_hex(updated_public_key) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(e)),
    };

    //create address from updated public key
    Ok(Address::from(updated_public_key.clone()).as_hex())
}

/// Decrypt value from Output Coin
/// Get Coin Output from Utxo Set and then decrypt
#[wasm_bindgen(js_name = decryptOutputValue)]
pub fn decrypt_output_value(seed: &str, output: String) -> Result<u64, JsValue> {
    //recreate zkosAccount
    let output: Output = serde_json::from_str(&output).unwrap();
    // check if output is of type coin
    match output.out_type {
        IOType::Coin => {
            let out_coin = match output.output.get_output_coin() {
                Some(out_coin) => out_coin,
                None => return Err(JsValue::from_str("No OutputCoin found in Output")),
            };

            //create ZkosAccount from out_coin
            let zk_account = ZkAccount::new(out_coin.owner.clone(), out_coin.encrypt);
            // get balance
            let json_zk_account = match serde_json::to_string(&zk_account) {
                Ok(j) => j,
                Err(e) => return Err(JsValue::from_str(&e.to_string())),
            };
            zk_account::decrypt_zk_account_value(seed, json_zk_account)
        }
        _ => return Err(JsValue::from_str("Invalid IOType. Expected Coin")),
    }
}

/// Create  Address as Hex string from a hex public key string.
/// Returns address as Hex directly .
///
#[wasm_bindgen(js_name = hexStandardAddressFromPublicKey)]
pub fn create_standard_hex_address_from_public_key(
    network: u8,
    key: String,
) -> Result<String, JsValue> {
    // Parse the string of data into a RistrettoPublicKey object.
    let pk = match public_key_from_hex(key) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    //create network byte. 12(std) | 24(contract)
    //for Mainnet, 44(std) | 66(contract) Testnet
    let net = match Network::from_u8(network) {
        Ok(net) => net,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    // Default AddressType for Public Key is Standard.

    Ok(Address::standard_address(net, pk).as_hex())
}

/// create pk from hex address
/// Output Pk as Hex String
///
#[wasm_bindgen(js_name = publicKeyFromHexAddress)]
pub fn create_public_key_from_standard_hex_address(hex_address: String) -> Result<String, JsValue> {
    //create Address
    let address = Address::from_hex(&hex_address, AddressType::Standard).unwrap();
    let pk: RistrettoPublicKey = address.into();

    Ok(public_key_to_hex(pk))
}

/// Extracts publickey Hex string from output
/// Input @output : Output as Json String Object.
/// Output @String : PublicKey as hex string.
///
#[wasm_bindgen(js_name = extractPublicKeyHexFromOutput)]
pub fn extract_public_key_hex_from_output_coin(output: String) -> Result<String, JsValue> {
    let out: Output = match serde_json::from_str(&output) {
        Ok(out) => out,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };

    // check if output is of type coin
    match out.out_type {
        IOType::Coin => {
            let out_coin = match out.output.get_output_coin() {
                Some(out_coin) => out_coin,
                None => return Err(JsValue::from_str("No OutputCoin found in Output")),
            };
            let address = Address::from_hex(&out_coin.owner, AddressType::Standard)?;
            let pk: RistrettoPublicKey = address.into();
            Ok(public_key_to_hex(pk))
        }
        _ => return Err(JsValue::from_str("Invalid Output type. Expected Coin")),
    }
}

/// extract owner address from output
/// Input @output : Output as Json String Object.
/// Output @String : Address as hex string.
#[wasm_bindgen(js_name = extractOwnerAddressFromOutput)]
pub fn extract_owner_address_from_output_coin(output: String) -> Result<String, JsValue> {
    let out: Output = match serde_json::from_str(&output) {
        Ok(out) => out,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    // check if output is of type coin
    match out.out_type {
        IOType::Coin => {
            let out_coin = match out.output.get_output_coin() {
                Some(out_coin) => out_coin,
                None => return Err(JsValue::from_str("No OutputCoin found in Output")),
            };
            Ok(out_coin.owner.clone())
        }
        _ => return Err(JsValue::from_str("Invalid Output type. Expected Coin")),
    }
}

/// Utility function to convert TxId into hex string
/// Returns TxId as hex string
#[wasm_bindgen(js_name = txIdToHexString)]
pub fn tx_id_to_hex_string(utxo: String) -> Result<String, JsValue> {
    let utxo: Utxo = serde_json::from_str(&utxo).unwrap();
    let tx_id_hex = utxo.tx_id_to_hex();
    Ok(tx_id_hex)
}

/// Function to create Utxo type from hex string
/// Returns Utxo object as Json string.
#[wasm_bindgen(js_name = createUtxoFromHex)]
pub fn create_utxo_from_hex_string(utxo_hex: String) -> Result<String, JsValue> {
    let utxo_bytes = hex::decode(&utxo_hex).unwrap();
    let utxo: Utxo = bincode::deserialize(&utxo_bytes).unwrap();

    let j = serde_json::to_string(&utxo);
    let msg_to_return = j.unwrap();
    Ok(msg_to_return)
}

/// convert hex scalar to json string
///
#[wasm_bindgen(js_name = convertHexScalarToJsonString)]
pub fn convert_hex_scalar_to_json(hex_scalar: String) -> Result<String, JsValue> {
    let scalar = match scalar_from_hex(hex_scalar) {
        Ok(scalar) => scalar,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    match serde_json::to_string(&scalar) {
        Ok(j) => Ok(j),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// create default utxo as Json string
///  Can be used for creating Utxo for Anonymity and Reciever accounts in Quisquis Transaction
#[wasm_bindgen(js_name = createDefaultUtxo)]
pub fn create_default_utxo() -> Result<String, JsValue> {
    let utxo = Utxo::default();
    match serde_json::to_string(&utxo) {
        Ok(j) => Ok(j),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// convert Utxo json Object into Hex String
#[wasm_bindgen(js_name = getUtxoHexFromJson)]
pub fn get_utxo_hex_from_json(utxo_json: String) -> Result<String, JsValue> {
    let utxo: Utxo = serde_json::from_str(&utxo_json).unwrap();
    let utxo_bytes = bincode::serialize(&utxo).unwrap();
    let utxo_hex = hex::encode(&utxo_bytes);
    Ok(utxo_hex)
}

// Function to check list of coin utxos against the provided secretkey
// Returns a list of all coin addresses that are owned by the secret key
#[wasm_bindgen(js_name = coinAddressMonitoring)]
pub fn coin_addrerss_monitoring(
    vector_utxo_output_str: String,
    seed: &str,
) -> Result<String, JsValue> {
    // create secret key from seed
    let sk: RistrettoSecretKey = hex_str_to_secret_key(&seed);

    let coin_address_vector =
        match twilight_client_sdk::util::coin_address_monitoring(vector_utxo_output_str, sk) {
            Ok(v) => v,
            Err(e) => return Err(JsValue::from_str(&e.to_string())),
        };
    // convert vector of addresses to Json string
    match serde_json::to_string(&coin_address_vector) {
        Ok(j) => Ok(j),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

// Function to select anonymity accounts from the set of utxos provided
// List of Inputs(derived from anonymity accounts) as json string
#[wasm_bindgen(js_name = selectAnonymityAccounts)]
pub fn select_anonymity_accounts(
    vector_utxo_output_str: String,
    sender_input: String,
) -> Result<String, JsValue> {
    // get the input from json string
    let input_sender: Input = match serde_json::from_str(&sender_input) {
        Ok(input) => input,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };

    let inputs_anonymity_vector =
        twilight_client_sdk::util::select_anonymity_accounts(vector_utxo_output_str, input_sender);
    match serde_json::to_string(&inputs_anonymity_vector) {
        Ok(j) => Ok(j),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen(js_name = convertMemoHextoJson)]
pub fn convert_memo_hex_to_json(hex_memo: String) -> Result<String, JsValue> {
    let memo_bytes = match hex::decode(&hex_memo) {
        Ok(bytes) => bytes,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let memo: OutputMemo = match bincode::deserialize(&memo_bytes) {
        Ok(memo) => memo,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    match serde_json::to_string(&memo) {
        Ok(j) => Ok(j),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}
