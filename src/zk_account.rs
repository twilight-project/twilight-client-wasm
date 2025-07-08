use crate::ElGamalCommitment;
use crate::*;
use ::transaction::quisquislib::accounts::Account;
use wasm_bindgen::prelude::*;
// ------- TendermintAccount ------- //
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkAccount {
    pub(crate) address: String,            // Hex String
    pub(crate) encrypt: ElGamalCommitment, // ElGamal Encryption of the amount
}

impl ZkAccount {
    pub fn new(address: String, encrypt: ElGamalCommitment) -> Self {
        Self { address, encrypt }
    }
    //encode the ZkAccount into a hex string for storage on chain
    //convert account to bare bytes and then encode the complete sequence to hex
    pub fn to_hex_str(&self) -> String {
        //reconstruct the Address from adress hex string to recreate bytes
        // to match the chain encoding
        let address: Address = Address::from_hex(&self.address, AddressType::Standard).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&address.as_bytes());
        bytes.extend_from_slice(&self.encrypt.to_bytes());
        let hex = hex::encode(bytes);
        hex
    }

    //decode the hex string into a ZkAccount with standard address
    pub fn from_hex_str(hex_str: String) -> Result<Self, &'static str> {
        let bytes = hex::decode(hex_str).unwrap();
        //let standard_address = Standard::from_bytes(&bytes[0..69]).unwrap();
        //let address = Address::Standard(standard_address);
        let address = Address::from_hex(&hex::encode(&bytes[0..69]), AddressType::Standard)?;
        let encrypt = ElGamalCommitment::from_bytes(&bytes[69..])?;
        Ok(Self {
            address: address.as_hex(),
            encrypt,
        })
    }
    // utility function to support the wallet monitoring
    pub fn verify_keypair(&self, sk: &RistrettoSecretKey) -> bool {
        //recreate account
        let account: Account = ZkAccount::into(self.clone());
        if account.verify_account_keypair(sk).is_ok() {
            true
        } else {
            false
        }
    }
}
// create ZkosAccount from Taditional quisquis Account
impl From<Account> for ZkAccount {
    fn from(account: Account) -> Self {
        let (pk, encrypt) = account.get_account();
        let address = Address::standard_address(Network::default(), pk);
        Self {
            address: address.as_hex(),
            encrypt,
        }
    }
}
// Implement the Into trait for your custom struct
// convert the Zkos account into a traditional QuisQuis Account
impl Into<Account> for ZkAccount {
    fn into(self) -> Account {
        let address = Address::from_hex(&self.address, AddressType::Standard).unwrap();
        let pub_key: RistrettoPublicKey = address.into();
        let encrypt = self.encrypt.clone();
        let account = Account::set_account(pub_key, encrypt);
        account
    }
}
impl Into<Output> for ZkAccount {
    fn into(self) -> Output {
        let encrypt = self.encrypt.clone();
        let output: Output = Output::coin(OutputData::coin(OutputCoin::new(
            encrypt,
            self.address.clone(),
        )));
        output
    }
}

impl From<Output> for ZkAccount {
    fn from(output: Output) -> Self {
        //check output type.
        //This only works for Coin Output
        match output.out_type {
            IOType::Coin => {
                let out_coin = output.output.get_output_coin().unwrap().to_owned();
                let address = out_coin.owner.clone();
                ZkAccount::new(address, out_coin.encrypt.clone())
            }
            _ => panic!("Invalid Output. Expected Coin type"),
        }
    }
}

/// Verify Public/Private Keypair.
/// Returns true iff the ZKAccount public key corresponds to private key
#[wasm_bindgen(js_name = verifyKeyPairZkAccount)]
pub fn verify_keypair_zk_account(seed: &str, acc: String) -> Result<bool, JsValue> {
    // create sk from seed
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);

    //recreate ZkAccount
    let acc = match ZkAccount::from_hex_str(acc) {
        Ok(acc) => acc,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    // recreate traditional quisquis Account
    let account: Account = ZkAccount::into(acc.clone());
    if account.verify_account_keypair(&sk).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

///Verify ZK Account.
/// Returns true iff the public key corresponds to private key
/// and the account balance commitment is equal to balance
///
#[wasm_bindgen(js_name = verifyZkAccount)]
pub fn verify_zk_account(seed: &str, acc: String, balance: u32) -> Result<bool, JsValue> {
    //derive private key
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);

    //recreate account
    let zk_acc = match ZkAccount::from_hex_str(acc) {
        Ok(zk_acc) => zk_acc,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    let acc: Account = ZkAccount::into(zk_acc.clone());
    if acc.verify_account(&sk, balance.into()).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Generate Zero balance Zkos Account with the provided hex address
/// Input is hex address as string
/// Output is ZkAccount as Hex string
#[wasm_bindgen(js_name = generateZeroBalaneZkAccountFromAddress)]
pub fn generate_zero_balance_zk_account_from_address(
    address_hex: String,
) -> Result<String, JsValue> {
    // Parse the string of data into a RistrettoPublicKey object.
    let address: Address = Address::from_hex(&address_hex, AddressType::Standard)?;
    let pk: RistrettoPublicKey = address.into();
    let comm_scalar = Scalar::random(&mut OsRng);
    let comm = ElGamalCommitment::generate_commitment(&pk, comm_scalar, Scalar::zero());

    let chain_account = ZkAccount::new(address_hex, comm);

    return Ok(chain_account.to_hex_str());
}

/// Generate zero balance Zk account with the provided key
/// Input : pk as Hex String
/// Output : ZkAccount as Hex String
#[wasm_bindgen(js_name = generateZeroBalaneZkAccountFromKey)]
pub fn generate_zero_zk_account_from_key(pk: String) -> Result<String, JsValue> {
    // Parse the string of data into a RistrettoPublicKey object.
    let pk = match public_key_from_hex(pk) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    let comm_scalar = Scalar::random(&mut OsRng);
    let comm = ElGamalCommitment::generate_commitment(&pk, comm_scalar, Scalar::zero());

    let chain_account = ZkAccount::new(
        Address::standard_address(Network::default(), pk).as_hex(),
        comm,
    );

    return Ok(chain_account.to_hex_str());
}

/// Generate ZkAccount with balance in the hex string format
/// Input @pk : Public Key as Hex String
/// Input @balance : Balance as u64
/// Input @r_scalar : Random Scalar as Hex String. used for creating the ecryption
/// Output : ZkAccount as Hex String
#[wasm_bindgen(js_name = generateZkAccountWithBalance)]
pub fn generate_zk_account_with_balance(
    pk: String,
    balance: u32,
    r_scalar: String,
) -> Result<String, JsValue> {
    // Parse the string of data into a RistrettoPublicKey object.
    let pk = match public_key_from_hex(pk) {
        Ok(pk) => pk,
        Err(e) => return Err(JsValue::from_str(e)),
    };

    let comm_scalar = match scalar_from_hex(r_scalar) {
        Ok(scalar) => scalar,
        Err(e) => return Err(JsValue::from_str(e)),
    };

    let comm =
        ElGamalCommitment::generate_commitment(&pk, comm_scalar, Scalar::from(balance as u64));

    let chain_account = ZkAccount::new(
        Address::standard_address(Network::default(), pk).as_hex(),
        comm,
    );

    return Ok(chain_account.to_hex_str());
}
/// Decrypt ZkAccount
/// Returns balance iff the public key corresponds to private key and the the encryption is valid
/// Input is ZkAccount as Hex String and seed is the signature seed from twilight wallet
/// Output is balance as u64
#[wasm_bindgen(js_name = decryptZkAccountValue)]
pub fn decrypt_zk_account_value(seed: &str, zk_acc: String) -> Result<u64, JsValue> {
    //derive private key
    let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);
    //recreate zkosAccount
    let trading_acc = match ZkAccount::from_hex_str(zk_acc) {
        Ok(acc) => acc,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    // get O.G Quisquis account
    let account: Account = trading_acc.into();
    //get balance
    let balance = account.decrypt_account_balance_value(&sk).unwrap();
    //convert balance into u64
    let scalar_bytes = balance.to_bytes();
    // Convert [u8; 32] into [u8; 8]
    let array_8: [u8; 8] = scalar_bytes[0..8].try_into().unwrap();
    Ok(u64::from_le_bytes(array_8))
}

/// getAddressFromZkAccountHex
///
#[wasm_bindgen(js_name = getAddressFromZkAccountHex)]
pub fn get_hex_address_from_zk_account_hex(acc_hex: String) -> Result<String, JsValue> {
    match ZkAccount::from_hex_str(acc_hex) {
        Ok(acc) => Ok(acc.address),
        Err(e) => Err(JsValue::from_str(e)),
    }
}

/// create Output from ZkAccount
/// Input @account : ZkAccount as Hex String
/// Returns Output as Json String Object.
///
#[wasm_bindgen(js_name = createOutputFromZkAccount)]
pub fn create_output_for_coin_from_zk_account(account: String) -> Result<String, JsValue> {
    let acc = match ZkAccount::from_hex_str(account) {
        Ok(acc) => acc,
        Err(e) => return Err(JsValue::from_str(e)),
    };

    let output: Output = acc.into();
    match serde_json::to_string(&output) {
        Ok(str) => Ok(str),
        Err(_) => return Err(JsValue::from_str("Error creating Output Json string")),
    }
}

/// create ZkAccount from Output (Coin)
/// Input @output : Output as Json String Object.
/// Returns ZkAccount as hex string.
///
#[wasm_bindgen(js_name = extractZkAccountFromOutput)]
pub fn extract_zk_account_from_output_coin(output: String) -> Result<String, JsValue> {
    let out: Output = serde_json::from_str(&output).unwrap();

    let account: ZkAccount = ZkAccount::from(out.clone());
    Ok(account.to_hex_str())
}

#[wasm_bindgen(js_name = updateZkAccount)]
pub fn update_zk_account(zk_account: String) -> Result<String, JsValue> {
    let acc = match ZkAccount::from_hex_str(zk_account) {
        Ok(acc) => acc,
        Err(e) => return Err(JsValue::from_str(e)),
    };
    let account: Account = acc.into();
    let key_scalar = Scalar::random(&mut OsRng);
    let commit_scalar = Scalar::zero();
    let updated_account =
        Account::update_account(account, Scalar::zero(), key_scalar, commit_scalar);
    let updated_account: ZkAccount = ZkAccount::from(updated_account);
    Ok(updated_account.to_hex_str())
}
