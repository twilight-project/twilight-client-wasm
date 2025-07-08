use crate::hex_str_to_secret_key;
use ::transaction::quisquislib::{
    accounts::Account,
    elgamal::ElGamalCommitment,
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

/// Wasm functions for the account module defined in the quisquis library
/// This module is not used in the current version of the ZK protocol
/// Leaving the functions here in case they are required later
///

///Verify Public/Private Keypair.
/// Returns true iff the traditional account public key corresponds to private key
///
#[wasm_bindgen(js_name = verifyKeyPairAccount)]
pub fn verify_keypair_account(seed: &str, acc: String) -> Result<bool, JsValue> {
    // create sk from seed
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);

    //recreate account
    let acc: Account = serde_json::from_str(&acc).unwrap();

    if acc.verify_account_keypair(&sk).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

///Verify traditional qq library Account.
/// Returns true iff the public key corresponds to private key and the account balance commitment is equal to balance
///
#[wasm_bindgen(js_name = verifyAccount)]
pub fn verify_account(seed: &str, acc: String, balance: u32) -> Result<bool, JsValue> {
    //derive private key
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);

    //recreate account
    let acc: Account = serde_json::from_str(&acc).unwrap();
    if acc.verify_account(&sk, balance.into()).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

///Decrypt Account.
/// Returns (G * balance) iff the public key corresponds to private key and the account balance commitment is equal to balance
///
#[wasm_bindgen(js_name = decryptAccountPoint)]
pub fn decrypt_account_point(seed: &str, acc: String, balance: u32) -> Result<String, JsValue> {
    //derive private key
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);
    //recreate account
    let acc: Account = serde_json::from_str(&acc).unwrap();

    let gv = acc.decrypt_account_balance(&sk, balance.into()).unwrap();
    let j = serde_json::to_string(&gv);
    let msg_to_return = j.unwrap();
    //returns G^v as CompressedRistretto string
    return Ok(msg_to_return);
}

///Generate Zro balance quisquis library account with the updated key.
/// Returns Account
///
#[wasm_bindgen(js_name = generateZeroAccount)]
pub fn generate_zero_account(pk_hex: String) -> Result<String, JsValue> {
    // Parse the string of data into a RistrettoPublicKey object.
    // Parse the string of data into a RistrettoPublicKey object.
    let pk: RistrettoPublicKey = match crate::public_key_from_hex(pk_hex) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let mut rng = OsRng;
    let random_scalar = Scalar::random(&mut rng);
    let updated_pk = RistrettoPublicKey::update_public_key(&pk, random_scalar);
    let (acc, _) = Account::generate_account(updated_pk);
    let j: Result<String, serde_json::Error> = serde_json::to_string(&acc);
    let msg_to_return = j.unwrap();

    return Ok(msg_to_return);
}

//returns traditional QQ account as defined in the library as Json string
#[wasm_bindgen(js_name = createQQAccountwithValueFromPk)]
pub fn create_qq_value_account_from_pk(pk_hex: String, balance: u32) -> Result<String, JsValue> {
    // Parse the string of data into a RistrettoPublicKey object.
    let pk: RistrettoPublicKey = match crate::public_key_from_hex(pk_hex) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(&e.to_string())),
    };
    let comm_scalar = Scalar::random(&mut OsRng);
    let comm =
        ElGamalCommitment::generate_commitment(&pk, comm_scalar, Scalar::from(balance as u64));

    let account = Account::set_account(pk, comm);
    let msg_to_return = serde_json::to_string(&account).unwrap();

    return Ok(msg_to_return);
}
