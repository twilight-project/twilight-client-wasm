#[cfg(test)]
mod test {

    use crate::*;
    pub fn create_pk_from_test_signature_string() -> String {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        let pk = crate::generate_public_key_from_signature(seed).unwrap();
        pk
    }

    #[test]
    fn test_generate_public_keys_from_signature() {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
        //println!("{:?}", sig_decoded);
        let result = crate::generate_public_key_from_signature(seed);
        println!("{:?}", result);
    }

    #[test]
    fn test_funding_trading_account() {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        let pk = create_pk_from_test_signature_string();
        let rscalar = crate::generate_random_scalar().unwrap();
        let trading_account =
            zk_account::generate_zk_account_with_balance(pk, 15000u32, rscalar).unwrap();

        let zkos_acc: ZkAccount = ZkAccount::from_hex_str(trading_account).unwrap();

        let pk_zkos: RistrettoPublicKey =
            Address::from_hex(&zkos_acc.address, AddressType::default())
                .unwrap()
                .into();
        let pk_zkos_json = serde_json::to_string(&pk_zkos).unwrap();
        let check = crate::verify_keypair(seed, pk_zkos_json).unwrap();

        let qq_acc = crate::Account::set_account(pk_zkos, zkos_acc.encrypt);
        let qq_acc_json = serde_json::to_string(&qq_acc).unwrap();
        let check_acc = crate::account::verify_account(seed, qq_acc_json.clone(), 10u32).unwrap();
        println!("check_acc {:?}", check_acc);
        println!("Trading account {:?}", zkos_acc);
    }
    #[test]
    fn test_get_script_address() {
        //let path = "./relayerprogram.json";
        // let script = contractmanager::get_contract_address(path.to_string());
        //  println!("script address {:?}", script);
    }

    //     #[test]
    //     fn test_get_encrypt_scalar() {
    //    let pk = create_pk_from_test_signature_string();
    //     //     let account = crate::generate_value_account(pk.clone(), 10u32).unwrap();
    //     //     let acc: crate::Account = serde_json::from_str(&account).unwrap();
    //     //     let (pk, enc) = acc.get_account();
    //     //     let c = enc.c();
    //     //     //Does Not Work
    //     // }
    #[test]
    fn test_update_key() {
        let key = create_pk_from_test_signature_string();
        // create random scalar for updation
        let rscalar = crate::generate_random_scalar().unwrap();
        let upk = update_public_key(key.clone(), rscalar.clone()).unwrap();
        let verify_result = verify_update_public_key(key, upk, rscalar).unwrap();

        assert_eq!(true, verify_result);
    }
    #[test]
    fn test_zero_account() {
        let pk = create_pk_from_test_signature_string();
        //println!("{:?}", result.unwrap());
        let r = account::generate_zero_account(pk.clone());
        println!("{:?}", r.unwrap());
    }
    #[test]
    fn test_keypair() {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
        let pk = generate_public_key_from_signature(seed).unwrap();
        let rscalar = crate::generate_random_scalar().unwrap();
        let upk = update_public_key(pk.clone(), rscalar.clone()).unwrap();

        // checking both the keys are linked to same sk
        let verify_pk = verify_keypair(seed, pk).unwrap();
        let verify_upk = verify_keypair(seed, upk).unwrap();
        assert_eq!(verify_pk, verify_upk);
        //println!("{:?}", result);
    }

    #[test]
    fn test_account_keypair() {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        let pk = create_pk_from_test_signature_string();
        println!("I'm here 2");
        let acc = account::generate_zero_account(pk.clone());
        println!("I'm here 3");
        let scalar = generate_random_scalar().unwrap();
        let upk = update_public_key(pk.clone(), scalar.clone()).unwrap();
        println!("I'm here 4");
        //let updated: UpdatedPublicKeyWasm = serde_json::from_str(&upk).unwrap();
        println!("I'm here 5");
        //let pk_str = serde_json::to_string(&updated.pk);
        //  let result = verify_keypair(&sig_passed_by_javascript, pk_str.unwrap()).unwrap();
        println!("I'm here 6");
        println!("acc : {:#?}", acc.clone().unwrap());
        let result = account::verify_keypair_account(seed, acc.unwrap());
        println!("I'm here 7");
        println!("{:?}", result);
    }

    #[test]
    fn test_account() {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        let pk = create_pk_from_test_signature_string();
        let acc = account::generate_zero_account(pk.clone());

        let result = account::verify_account(seed, acc.unwrap(), 0u32.into());
        println!("{:?}", result);
    }

    #[test]
    fn test_account_decrypt() {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        let pk = create_pk_from_test_signature_string();
        let acc = account::generate_zero_account(pk.clone());

        let result = account::decrypt_account_point(&seed, acc.unwrap(), 0u32.into());
        println!("{:?}", result);
    }
    #[test]
    fn test_account_generate() {
        let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        let pk = create_pk_from_test_signature_string();
        let acc_str = account::create_qq_value_account_from_pk(pk.clone(), 10u32.into()).unwrap();
        //re-create AccountWasm
        let acc_wasm: Account = serde_json::from_str(&acc_str).unwrap();
        let result = account::decrypt_account_point(seed, acc_str.clone(), 10u32.into());
        println!("{:?}", result);
    }
    // #[test]
    // fn test_generate_chain_funding_trading_account() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

    //     let pk = create_pk_from_test_signature_string();
    //     let fund_trade_acc_str =
    //         crate::generate_chain_funding_trading_account(pk.clone(), 8000u32).unwrap();

    //     //re-create FundingAccount and ChainQQAccount
    //     let acc_funding_trading: FundingZkAccountHex =
    //         serde_json::from_str(&fund_trade_acc_str).unwrap();
    //     println!("Funding account {:?}", acc_funding_trading);

    //     //reconstruct scalar
    //     let scalar_decode = hex::decode(&acc_funding_trading.encrypt_scalar_hex).unwrap();
    //     let scalar = Scalar::from_bytes_mod_order(scalar_decode.try_into().unwrap());
    //     println!("{:?}", scalar);

    //     //convert funding account to ZkAccount
    //     let acc_trade: String = crate::funding_to_trading_account(fund_trade_acc_str).unwrap();

    //     let trade_account: ZkAccount = serde_json::from_str(&acc_trade).unwrap();

    //     let account_address = trade_account.address;
    //     println!("{:?}", account_address);

    //     //convert Zk account to account
    //     let acc = Account::set_account(
    //         serde_json::from_str(&pk).unwrap(),
    //         trade_account.encrypt.clone(),
    //     );
    //     let acc_string = serde_json::to_string(&acc).unwrap();
    //     let result = account::decrypt_account_point(seed, acc_string.clone(), 1464u32.into());
    //     println!("{:?}", result);
    // }
    #[test]
    fn test_utxo_encoding_decoding() {
        let utx_str = crate::create_default_utxo().unwrap();
        println!("utxo_str: {}", utx_str);
        let utx: Utxo = serde_json::from_str(&utx_str).unwrap();
        println!("{:?}", utx);
        //let ut: Utxo = bincode::deserialize(&utx).unwrap();
        //println!("{:?}", ut);
    }

    #[test]
    fn test_decrypt_account_value() {
        let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";

        let pk = generate_public_key_from_signature(seed).unwrap();
        let rscalar = crate::generate_random_scalar().unwrap();
        let acc_str =
            zk_account::generate_zk_account_with_balance(pk.clone(), 10572u32.into(), rscalar)
                .unwrap();

        let balance = zk_account::decrypt_zk_account_value(seed, acc_str.clone()).unwrap();
        println!("{:?}", balance);
    }

    // #[test]
    // fn test_create_quisquis_account_general_transaction_test() {
    //     // lets say bob wants to sent 5 tokens to alice from his one account and 2 from his other account to fay
    //     // and 1 token to jay

    //     let bob_account_sig_1: [u8; 65] = [
    //         96, 122, 166, 237, 232, 200, 61, 103, 226, 227, 181, 67, 174, 45, 234, 147, 189, 223, 212,
    //         215, 123, 5, 253, 15, 203, 189, 59, 237, 72, 86, 94, 165, 45, 118, 235, 15, 178, 47, 94,
    //         92, 216, 41, 75, 100, 129, 236, 205, 80, 69, 203, 59, 72, 234, 19, 108, 148, 57, 53, 150,
    //         145, 0, 130, 126, 166, 27,
    //     ];
    //     let bob_account_sig_1_str = base64::encode(&bob_account_sig_1);
    //     let bob_account_sig_2: [u8; 65] = [
    //         96, 122, 166, 237, 232, 200, 61, 103, 226, 227, 181, 67, 174, 45, 234, 147, 189, 223, 212,
    //         215, 123, 5, 251, 15, 203, 189, 59, 237, 72, 86, 94, 165, 45, 118, 235, 15, 178, 47, 94,
    //         92, 216, 41, 75, 103, 129, 236, 205, 80, 69, 203, 59, 72, 234, 19, 108, 148, 57, 53, 150,
    //         145, 0, 130, 127, 166, 27,
    //     ];
    //     let bob_account_sig_2_str = base64::encode(&bob_account_sig_2);

    //     // lets create sender accounts to send these amounts from
    //     let bob_pk_1 = generate_public_key_from_signature(&bob_account_sig_1).unwrap();
    //     let bob_account_scalar = generate_account(bob_pk_1.clone(), 10u32).unwrap();
    //     let bob_account_1:AccountWasm = serde_json::from_str(&bob_account_scalar).unwrap();
    //     let bob_acc_1_str = bob_account_1.account.clone();

    //     let bob_pk_2 = generate_public_key_from_signature(&bob_account_sig_2).unwrap();
    //     let bob_account_scalar_2 = generate_account(bob_pk_2.clone(), 20u32).unwrap();
    //     let bob_acc_2: AccountWasm = serde_json::from_str(&bob_account_scalar_2).unwrap();
    //     let bob_acc_2_str = bob_acc_2.account.clone();

    //     // lets create receiver pks
    //     let alice_sk: [u8; 65] = [
    //         96, 122, 166, 237, 232, 200, 61, 103, 226, 225, 181, 67, 174, 45, 234, 147, 189, 223, 212,
    //         215, 123, 5, 253, 15, 203, 189, 60, 237, 72, 86, 95, 165, 45, 118, 235, 15, 178, 47, 94,
    //         92, 216, 41, 75, 100, 129, 236, 205, 80, 69, 203, 59, 72, 234, 19, 108, 148, 57, 53, 150,
    //         145, 0, 130, 126, 166, 27,
    //     ];
    //     let fay_sk: [u8; 65] = [
    //         96, 122, 166, 237, 232, 200, 61, 105, 226, 227, 181, 67, 174, 45, 234, 147, 189, 223, 212,
    //         215, 123, 5, 253, 15, 203, 189, 59, 236, 72, 86, 94, 165, 45, 118, 235, 15, 178, 47, 94,
    //         92, 216, 41, 75, 100, 129, 236, 205, 84, 69, 203, 59, 72, 234, 19, 108, 148, 57, 53, 150,
    //         145, 0, 130, 126, 166, 27,
    //     ];
    //     let jay_sk: [u8; 65] = [
    //         96, 122, 166, 237, 232, 200, 61, 103, 226, 227, 181, 67, 174, 45, 234, 147, 189, 223, 212,
    //         215, 123, 5, 253, 14, 203, 189, 59, 237, 72, 86, 94, 165, 45, 118, 235, 15, 178, 47, 94,
    //         92, 216, 42, 75, 100, 129, 236, 203, 80, 69, 203, 59, 72, 234, 19, 108, 148, 57, 53, 150,
    //         145, 0, 130, 126, 166, 27,
    //     ];
    //     let alice_pk = generate_public_key_from_signature(&alice_sk).unwrap();
    //     let alice_account = generate_zero_account(alice_pk.clone()).unwrap();
    //     let fay_pk = generate_public_key_from_signature(&fay_sk).unwrap();
    //     let fay_account = generate_zero_account(fay_pk.clone()).unwrap();
    //     let jay_pk = generate_public_key_from_signature(&jay_sk).unwrap();
    //     let jay_account = generate_zero_account(jay_pk.clone()).unwrap();
    //     // so we have 2 senders and 3 receivers, rest will be the anonymity set

    //     let tx_vector: Vec<SenderWasm> = vec![
    //         SenderWasm {
    //             total_amount: -5,
    //             account: bob_acc_1_str.clone(),
    //             receivers: vec![RecieverWasm {
    //                 amount: 5,
    //                 account: alice_account,
    //             }],
    //         },
    //         SenderWasm {
    //             total_amount: -10,
    //             account: bob_acc_2_str.clone(),
    //             receivers: vec![
    //                 RecieverWasm {
    //                     amount: 7,
    //                     account: fay_account,
    //                 },
    //                 RecieverWasm {
    //                     amount: 3,
    //                     account: jay_account,
    //                 },
    //             ],
    //         },
    //     ];

    //     let tx_vector_str = serde_json::to_string(&tx_vector).unwrap();

    //     //Create sender updated account vector for the verification of sk and bl-v
    //     let bl_first_sender = 10 - 5; //bl-v
    //     let bl_second_sender = 20 - 10; //bl-v

    //     let updated_balance_sender: Vec<i64> = vec![bl_first_sender, bl_second_sender];

    //     let upd_bl_sender_str = serde_json::to_string(&updated_balance_sender).unwrap();

    //     //Create vector of sender secret keys
    //     let sk_sender: Vec<String> = vec![bob_account_sig_1_str.clone(), bob_account_sig_2_str.clone()];
    //     let sk_sender_str = serde_json::to_string(&sk_sender).unwrap();

    //     //create a vector of updated receiver balances
    //    let updated_recevier_balance: Vec<u64> = vec![5, 7, 3];
    //     let updated_recevier_balance_str =
    //         serde_json::to_string(&updated_recevier_balance).unwrap();

    //     let tx: Result<String, JsValue> = super::create_quisquis_transaction(
    //         tx_vector_str,
    //         sk_sender_str,
    //         upd_bl_sender_str,
    //         updated_recevier_balance_str,
    //     );
    //     let verify_string = tx.clone().unwrap();

    //     println!("verify :: {:?}", super::verify_quisquis_tx(verify_string));
    // }

    // #[test]
    // fn test_create_trader_order_zkos() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();

    //     let account_id = "account_id";
    //     let position_type = "SHORT";
    //     let order_type = "MARKET";
    //     let leverage = 10.0;
    //     let initial_margin: f64 = 2.0;
    //     let available_margin: f64 = 2.0;
    //     let order_status = "PENDING";
    //     let entryprice = 12900.1;
    //     let execution_price = 44440.02;

    //     //mimic frontend information
    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 10u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();

    //     let out_coin =
    //         crate::create_output_for_coin_from_trading_account(zkos_acc.clone()).unwrap();
    //     let utxo = Utxo::default();
    //     let utx = serde_json::to_string(&utxo).unwrap();

    //     let input =
    //         crate::relayer_ops::create_input_from_output(out_coin.clone(), utx, 0u64).unwrap();
    //     let address: String =
    //         relayer_ops::get_hex_address_from_trading_account(zkos_acc.clone()).unwrap();

    //     let funding: FundingZkAccountHex = serde_json::from_str(&fund_acc).unwrap();
    //     let encrypt_scalar_hex = funding.encrypt_scalar_hex;
    //     //create output memo
    //     let memo = crate::relayer_ops::create_output_for_memo(
    //         crate::relayer_ops::get_harcoded_script_address().unwrap(),
    //         address,
    //         10u64,
    //         10,
    //         encrypt_scalar_hex.clone(),
    //     )
    //     .unwrap();
    //     //let memo : Output = serde_json::from_str(&memo).unwrap();

    //     //let input : Input = serde_json::from_str(&input).unwrap();
    //     //create coin input

    //     let order: String = crate::relayer_ops::create_trader_order_zkos(
    //         input,
    //         memo,
    //         seed,
    //         encrypt_scalar_hex.clone(),
    //         10u64,
    //         account_id.to_string(),
    //         position_type.to_string(),
    //         order_type.to_string(),
    //         leverage,
    //         initial_margin,
    //         available_margin,
    //         order_status.to_string(),
    //         entryprice,
    //         execution_price,
    //     )
    //     .unwrap();
    //     println!("{:?}", order);
    // }
    // #[test]
    // fn test_create_lend_order_zkos() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();
    //     //mimic frontend information
    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 10u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();

    //     let out_coin =
    //         crate::create_output_for_coin_from_trading_account(zkos_acc.clone()).unwrap();
    //     let utxo = Utxo::default();
    //     let utx = serde_json::to_string(&utxo).unwrap();

    //     let input =
    //         crate::relayer_ops::create_input_from_output(out_coin.clone(), utx, 0u64).unwrap();
    //     let address: String =
    //         relayer_ops::get_hex_address_from_trading_account(zkos_acc.clone()).unwrap();

    //     let funding: FundingZkAccountHex = serde_json::from_str(&fund_acc).unwrap();
    //     let encrypt_scalar_hex = funding.encrypt_scalar_hex;

    //     //create output memo
    //     let memo = crate::relayer_ops::create_output_for_memo(
    //         crate::relayer_ops::get_harcoded_script_address().unwrap(),
    //         address,
    //         10u64,
    //         10,
    //         encrypt_scalar_hex.clone(),
    //     )
    //     .unwrap();
    //     //let memo : Output = serde_json::from_str(&memo).unwrap();

    //     //let input : Input = serde_json::from_str(&input).unwrap();
    //     //create coin input

    //     let account_id = "account_id";
    //     let balance: f64 = 10.0;
    //     let order_type = "LEND";
    //     let order_status = "PENDING";
    //     let deposit = 9.0;

    //     let order: String = crate::relayer_ops::create_lend_order_zkos(
    //         input,
    //         memo,
    //         seed,
    //         encrypt_scalar_hex.clone(),
    //         10u64,
    //         account_id.to_string(),
    //         balance,
    //         order_type.to_string(),
    //         order_status.to_string(),
    //         deposit,
    //     )
    //     .unwrap();
    //     println!("{:?}", order);
    // }

    // #[test]
    // fn test_cancel_trader_order_zkos() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();
    //     //mimic frontend information
    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 10u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();
    //     let address: String =
    //         relayer_ops::get_hex_address_from_trading_account(zkos_acc.clone()).unwrap();

    //     let uuid = Uuid::parse_str("936DA01F-9ABD-4D9D-80C7-02AF85C822A8").unwrap();
    //     let uid_ex = hex::encode(&uuid.as_bytes());
    //     let uuid_str: String = serde_json::to_string(&uid_ex).unwrap();

    //     let cancel_order = crate::relayer_ops::cancel_trader_order_zkos(
    //         address,
    //         seed,
    //         "account_id".to_string(),
    //         uuid_str,
    //         "LIMIT".to_string(),
    //         "CANCELLED".to_string(),
    //     )
    //     .unwrap();
    //     println!("cancel order  {:?}", cancel_order);
    // }

    // #[test]
    // fn test_settle_order() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();

    //     let account_id = "account_id";
    //     let uuid: Uuid = Uuid::parse_str("4e8b7256-a089-4fc3-80af-027ea6cd0099").unwrap();
    //     let order_type = "MARKET";
    //     let order_status = "PENDING";
    //     let settle_margin: f64 = 0.0;
    //     let execution_price: f64 = 44440.02;
    //     let tx_type = "ORDERTX";

    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 10u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();
    //     let address: String =
    //         relayer_ops::get_hex_address_from_trading_account(zkos_acc.clone()).unwrap();

    //     let funding: FundingZkAccountHex = serde_json::from_str(&fund_acc).unwrap();
    //     let encrypt_scalar: String = funding.encrypt_scalar_hex;

    //     //create output memo
    //     let utxo = Utxo::default();
    //     let utx = serde_json::to_string(&utxo).unwrap();
    //     let memo = crate::relayer_ops::create_output_for_memo(
    //         crate::relayer_ops::get_harcoded_script_address().unwrap(),
    //         address,
    //         10u64,
    //         10,
    //         encrypt_scalar.clone(),
    //     )
    //     .unwrap();
    //     let input = crate::relayer_ops::create_input_from_output(memo.clone(), utx, 0u64).unwrap();

    //     let res = crate::relayer_ops::execute_order_zkos(
    //         input,
    //         seed,
    //         account_id.to_string(),
    //         serde_json::to_string(&uuid).unwrap(),
    //         order_type.to_string(),
    //         settle_margin,
    //         order_status.to_string(),
    //         execution_price,
    //         tx_type.to_string(),
    //     )
    //     .unwrap();
    //     println!("settle request {:?}", res);
    // }

    // #[test]
    // fn test_query_trader_order_zkos() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();

    //     //mimic frontend information
    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 10u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();
    //     let address: String =
    //         relayer_ops::get_hex_address_from_trading_account(zkos_acc.clone()).unwrap();

    //     let query_order = crate::relayer_ops::query_trader_order_zkos(
    //         address,
    //         seed,
    //         "account_id".to_string(),
    //         "PENDING".to_string(),
    //     )
    //     .unwrap();
    //     println!("Query order  {:?}", query_order);
    // }

    // #[test]
    // fn test_query_lend_order_zkos() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();

    //     //mimic frontend information
    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 10u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();
    //     let address: String =
    //         relayer_ops::get_hex_address_from_trading_account(zkos_acc.clone()).unwrap();

    //     let query_order = crate::relayer_ops::query_lend_order_zkos(
    //         address,
    //         seed,
    //         "account_id".to_string(),
    //         "PENDING".to_string(),
    //     )
    //     .unwrap();
    //     println!("cancel order  {:?}", query_order);
    // }

    // #[test]
    // fn test_create_trader_order_and_query_zkos() {
    //     let seed: &str = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();

    //     let account_id = "account_id";
    //     let position_type = "SHORT";
    //     let order_type = "MARKET";
    //     let leverage = 10.0;
    //     let initial_margin: f64 = 2.0;
    //     let available_margin: f64 = 2.0;
    //     let order_status = "PENDING";
    //     let entryprice = 12900.1;
    //     let execution_price = 44440.02;

    //     //mimic frontend information
    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 10u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();

    //     let out_coin =
    //         crate::create_output_for_coin_from_trading_account(zkos_acc.clone()).unwrap();
    //     let utxo = Utxo::default();
    //     let utx = serde_json::to_string(&utxo).unwrap();

    //     let input =
    //         crate::relayer_ops::create_input_from_output(out_coin.clone(), utx, 0u64).unwrap();
    //     let address: String =
    //         relayer_ops::get_hex_address_from_trading_account(zkos_acc.clone()).unwrap();

    //     let funding: FundingZkAccountHex = serde_json::from_str(&fund_acc).unwrap();
    //     let encrypt_scalar: String = funding.encrypt_scalar_hex;

    //     //create output memo
    //     let memo = crate::relayer_ops::create_output_for_memo(
    //         crate::relayer_ops::get_harcoded_script_address().unwrap(),
    //         address.clone(),
    //         10u64,
    //         10,
    //         encrypt_scalar.clone(),
    //     )
    //     .unwrap();
    //     //let memo : Output = serde_json::from_str(&memo).unwrap();

    //     //let input : Input = serde_json::from_str(&input).unwrap();
    //     //create coin input

    //     let order: String = crate::relayer_ops::create_trader_order_zkos(
    //         input,
    //         memo,
    //         seed,
    //         encrypt_scalar,
    //         10u64,
    //         account_id.to_string(),
    //         position_type.to_string(),
    //         order_type.to_string(),
    //         leverage,
    //         initial_margin,
    //         available_margin,
    //         order_status.to_string(),
    //         entryprice,
    //         execution_price,
    //     )
    //     .unwrap();
    //     println!("{:?}", order);

    //     let query_order = crate::relayer_ops::query_trader_order_zkos(
    //         address,
    //         seed,
    //         "account_id".to_string(),
    //         "PENDING".to_string(),
    //     )
    //     .unwrap();
    //     println!("order query  {:?}", query_order);
    // }
    #[test]
    fn test_read_all_utxo_set() {
        let utxo_str: Vec<&str> = [
            "c48548aba9be60ac7e9fbc3735e6f706955db554cf419edd159e3fd8c4c4100500",
            "4554ee117a4ff1f62f52a4b4d150da611cea34b4db0c13f8c46dbb767aa5923100",
            "d091a69d04e5076c5efdb38fc8b1da4f856c2d12c73253dc2af2f98052bbef2200",
            "ae821bebc9d352af384622b603c12d36d4cc330bbdeeef3717ff2a034b4e7efa01",
            "7de9f3368fdba3e23ced4ab9f425475c848cfad5e62b692ae9dab70b374f087f03",
            "9bf23d2bbe668dfe3bd016974ecd78b109801b1b900de529137cc4ea9d4a56d500",
            "ae821bebc9d352af384622b603c12d36d4cc330bbdeeef3717ff2a034b4e7efa02",
            "ae821bebc9d352af384622b603c12d36d4cc330bbdeeef3717ff2a034b4e7efa04",
            "1904164809c13a383ebfbf38b7a51304d1d417a583f3c83cf8be6c4ee4b206ab00",
            "c1fd83156b076f7ae0fd183543982410de51b200b82216c2ae69373a44d5d9d900",
            "f7ed6aa5dd79688d3d2cc085bce869314a40b44b4643f8fc1ad82ae037fe036100",
            "2eb56c67188156758d2b6a71903b2314349e56e18f492c83f6a293c197a478b900",
            "a2676269d992dbd945eaacf7790268f50b2c00a2ea1e0635199b875726ccdc6200",
            "569a539ad96d4177bb139eb036d3d94af8f64fa243ea92dea5be6ff24040eb9300",
            "ae821bebc9d352af384622b603c12d36d4cc330bbdeeef3717ff2a034b4e7efa00",
            "39ea7be7d3dd3a256238b10736424f5dba303a6fcaccd277dbbeaac03336447904",
            "7de9f3368fdba3e23ced4ab9f425475c848cfad5e62b692ae9dab70b374f087f02",
            "2e378e545ad8d064ce8cb9a1906afbb90e85fb28b1a4d1bef02e8a5cd03a039c00",
            "39ea7be7d3dd3a256238b10736424f5dba303a6fcaccd277dbbeaac03336447901",
            "7de9f3368fdba3e23ced4ab9f425475c848cfad5e62b692ae9dab70b374f087f04",
            "ae821bebc9d352af384622b603c12d36d4cc330bbdeeef3717ff2a034b4e7efa03",
            "1bbe7a3496b5d17a32016efdba4be933a65bd32110210eb3347a4b63befb9b7300",
            "8fc143313395701c4cccc0d46ec23efefeaedcc3281124acf2d85ca3810706a200",
            "2a3a48eea828ca35aa27a1601b2e8be9c42352e857353f26d71f089b9d147e5300",
            "39ea7be7d3dd3a256238b10736424f5dba303a6fcaccd277dbbeaac03336447902",
            "1ef6951958e9e3e6584546b4fa7d6a402b29387efcaa27645acfb5d44087b4a700",
            "80774a862e5c26decff3a6c73a19414dccd05dca0d1f0c9f06a6d4664c72e33e00",
            "cb867c3f65a073e54d54eac8bb2d9f7fd76866536cc71953f9840a85377a842e00",
            "39ea7be7d3dd3a256238b10736424f5dba303a6fcaccd277dbbeaac03336447900",
            "dbd495697b929e315a355c5a49b32176b2750a5b8ab821f17f79c1aa8813b80300",
            "3500eec55b4e04b0b15e3f0d36edee1659ce9c2f60cc21628ffa72a28498419e00",
        ]
        .to_vec();
        //read all utxo
        //recreate utxos from Json Strings
        let utxo_vec: Vec<Utxo> = utxo_str
            .iter()
            .map(|i| Utxo::from_bytes(&hex::decode(&i).unwrap()).unwrap())
            .collect();
        println!("utxo_vec: {:?}", utxo_vec);
    }

    // #[test]
    // fn test_create_trading_account_from_output_coin() {
    //     //create output coin of value 12343
    //     let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";

    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();

    //     let fund_acc: String = crate::generate_chain_funding_trading_account(key, 123u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();
    //     let out_coin =
    //         crate::create_output_for_coin_from_trading_account(zkos_acc.clone()).unwrap();
    //     //recreate output coin
    //     let output: Output = serde_json::from_str(&out_coin).unwrap();
    //     let trading_acc_from_coin = ZkAccount::from(output.clone());
    //     println!("zkos_acc_from_coin {:?}", trading_acc_from_coin);
    // }

    // #[test]
    // fn test_signature_encoding_decoding() {
    //     use base64::Engine;
    //     let sign_bytes: [u8; 64] = [
    //         193, 166, 149, 92, 153, 215, 33, 132, 29, 216, 17, 184, 173, 80, 53, 218, 174, 78, 78,
    //         231, 45, 205, 192, 237, 236, 18, 242, 31, 14, 216, 199, 253, 91, 218, 32, 197, 174, 94,
    //         36, 57, 192, 191, 86, 91, 196, 222, 219, 203, 102, 174, 195, 119, 250, 146, 136, 193,
    //         29, 96, 173, 67, 188, 51, 230, 103,
    //     ];

    //     let sign_str = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";

    //     let mut buffer = Vec::<u8>::new();
    //     general_purpose::STANDARD
    //         .decode_vec(sign_str, &mut buffer)
    //         .unwrap();
    //     //base64::decode(sign_str).unwrap();
    //     assert_eq!(sign_bytes.to_vec(), buffer);

    //     //let tes = decode_from_base64(sign_str);
    //     //println!("tes {:?}", tes);
    // }
    // #[test]
    // fn test_decrypt_output_value() {
    //     //create output coin of value 12343
    //     let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";

    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();
    //     let fund_acc: String =
    //         crate::generate_chain_funding_trading_account(key, 12343u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();
    //     let out_coin =
    //         crate::create_output_for_coin_from_trading_account(zkos_acc.clone()).unwrap();

    //     let value = decrypt_output_value(seed, out_coin).unwrap();
    //     println!("value {:?}", value);
    // }
    #[test]
    fn test_generate_random_address() {
        //create public key
        let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";

        //create pk from signature
        let key = generate_public_key_from_signature(seed).unwrap();

        let address = generate_random_address(key).unwrap();
        println!("address {:?}", address);
    }
    // #[test]
    // fn test_get_funding_account_hex_from_output() {
    //     let sig_passed_by_javascript: [u8; 65] = [
    //         96, 122, 166, 237, 232, 200, 61, 103, 226, 227, 181, 67, 174, 45, 234, 147, 189, 223,
    //         212, 215, 123, 5, 253, 15, 203, 189, 59, 237, 72, 86, 94, 165, 45, 118, 235, 15, 178,
    //         47, 94, 92, 216, 41, 75, 100, 129, 236, 205, 80, 69, 203, 59, 72, 234, 19, 108, 148,
    //         57, 53, 150, 145, 0, 130, 126, 166, 27,
    //     ];
    //     //create pk from signature
    //     //create output coin of value 12343
    //     let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";

    //     //create pk from signature
    //     let key = generate_public_key_from_signature(seed).unwrap();
    //     let fund_acc: String =
    //         crate::generate_chain_funding_trading_account(key, 12343u32).unwrap();
    //     let zkos_acc = crate::funding_to_trading_account(fund_acc.clone()).unwrap();
    //     let out_coin =
    //         crate::create_output_for_coin_from_trading_account(zkos_acc.clone()).unwrap();
    //     let funding_trading_account_hex =
    //         crate::relayer_ops::get_funding_trading_account_hex_from_output(out_coin, 12343)
    //             .unwrap();
    //     println!("funding_account_hex {:?}", funding_trading_account_hex);
    // }
    #[test]
    fn test_trading_account_hex_encoding_decoding() {
        let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";
        //create pk from signature
        let key = generate_public_key_from_signature(seed).unwrap();
        // create account
        let acc_str = crate::account::create_qq_value_account_from_pk(key, 15u32).unwrap();
        let account: Account = serde_json::from_str(&acc_str).unwrap();
        let trading_account: ZkAccount = ZkAccount::from(account);
        let add_len = trading_account.address.len();
        let enc_len = trading_account.encrypt.to_bytes().len();

        let t_hex = trading_account.to_hex_str().len();

        println!("trading acc : {:?}", trading_account);
        println!(
            "add len : {:?} , enc_len: {:?} , len: {:?}",
            add_len, enc_len, t_hex
        );
    }
    // #[test]
    // fn test_coin_addrerss_monitoring() {
    //     let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";
    //     // creata a test Vector of utxos
    //     let mut vector_utxo_output_raw = Vec::<UtxoOutputRawWasm>::new();

    //     for _i in 0..5 {
    //         //create pk from signature
    //         let key = generate_public_key_from_signature(seed).unwrap();
    //         let acc_str = crate::account::generate_value_account(key, 15u32).unwrap();
    //         let account: Account = serde_json::from_str(&acc_str).unwrap();
    //         let output = Output::from(account);
    //         let output_bytes = bincode::serialize(&output).unwrap();
    //         let utxo = Utxo::random();
    //         let utxo_key = bincode::serialize(&utxo).unwrap();
    //         let utxo_output_wasm = UtxoOutputRawWasm::new(utxo_key, output_bytes, 10i64);
    //         vector_utxo_output_raw.push(utxo_output_wasm);
    //     }
    //     let utxo_output_raw_hex =
    //         hex::encode(&bincode::serialize(&vector_utxo_output_raw).unwrap());

    //     let addresses = crate::coin_addrerss_monitoring(utxo_output_raw_hex, seed).unwrap();
    //     println!("addresses {:?}", addresses);
    // }

    // #[test]
    // fn test_select_anonymity_accounts() {
    //     let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";
    //     // creata a test Vector of utxos
    //     let mut vector_utxo_output_raw = Vec::<UtxoOutputRawWasm>::new();
    //     // create a sender
    //     let key = generate_public_key_from_signature(seed).unwrap();
    //     let acc_str = crate::account::generate_value_account(key, 15u32).unwrap();
    //     let account: Account = serde_json::from_str(&acc_str).unwrap();
    //     let output = Output::from(account);
    //     let output_bytes = bincode::serialize(&output).unwrap();
    //     let utxo = Utxo::random();
    //     let utxo_key = bincode::serialize(&utxo).unwrap();
    //     let utxo_output_wasm = UtxoOutputRawWasm::new(utxo_key, output_bytes, 10i64);
    //     vector_utxo_output_raw.push(utxo_output_wasm);
    //     // convert output to json string
    //     let sender_output_json = serde_json::to_string(&output).unwrap();
    //     // convert utxo to json string
    //     let sender_utxo_json = serde_json::to_string(&utxo).unwrap();
    //     // create input from output
    //     let sender_inp = crate::relayer_ops::create_input_from_output(
    //         sender_output_json,
    //         sender_utxo_json,
    //         0u64,
    //     )
    //     .unwrap();
    //     for _i in 0..9 {
    //         //create pk from signature
    //         let key = generate_public_key_from_signature(seed).unwrap();
    //         let acc_str = crate::account::generate_value_account(key, 15u32).unwrap();
    //         let account: Account = serde_json::from_str(&acc_str).unwrap();
    //         let output = Output::from(account);
    //         let output_bytes = bincode::serialize(&output).unwrap();
    //         let utxo = Utxo::random();
    //         let utxo_key = bincode::serialize(&utxo).unwrap();
    //         let utxo_output_wasm = UtxoOutputRawWasm::new(utxo_key, output_bytes, 10i64);
    //         vector_utxo_output_raw.push(utxo_output_wasm);
    //     }
    //     let utxo_output_raw_hex =
    //         hex::encode(&bincode::serialize(&vector_utxo_output_raw).unwrap());

    //     let anony = crate::select_anonymity_accounts(utxo_output_raw_hex, sender_inp).unwrap();
    //     println!("addresses {:?}", anony);
    // }

    #[test]
    fn test_deployed_data() {
        let db_data = "2c000000000000002100000000000000afcbea536aa839253ca4517125f1fce00f2ee96793f4f0323
        d481203ee4de29a00da0000000000000000000000000000009cd2760c5169fe030d016d162f9698d987662698370cdf2d8d2e4a7756803d630a953e3cf14eb9f3a0fa4751fd3d417d09c2eaea0b9a28a878bccc44288db5668a000000000000003063303834363731653333643861353439643030386432343866373761666361333930363233643639346461663464303066383962363364313434333331666630666532333031303463316563653134303438303139613462383437396236333436313735376265333865393035343839626331633036373465666334316565346634313830353038661e9c0700000000002100000000000000afcbea536aa839253ca4517125f1fce00f2ee96793f4f032
        3d481203ee4de29a01da0000000000000000000000000000003698e1cfabfdc65adbe469327f6b41603310e0a67d977d9f00183ac5ca50d84ca
        8abdd5b44ae617460fd360c664cd6103439d33d5017a24915533f9e7d1a51528a00000000000000306364303665656639343732353832
        6639303030643537383166323039613833616166613238386130383730653533306139313939636361643866303833333432643132656434356
        564393833613335626136333238366137356333323263356431306534643931393265643334643763623033613063326631326238376638353133
        613062363936611e9c07000000000021000000000000007bb9921c7293f249f599b34de2a04002d3d8e9e08ed7dea5b0aec15e75c83dca01da000
        000000000000000000000000000cc6604cdb6991c4df3aaf56599582fa2a60ca6dbd0a263a9556c7d9ce02d0835dad568b5d90da837b27b148d3c
        c1125bda59ed317d10eec7c7fa5fa0c6375e7f8a00000000000000306331613833333933326538633163313339663530333764303832633765613
        73635646464663330343530313362656536346531356139303637363132363966303263323765613933303432363937386364643331633436343
        1383539663562633839326131616634626437393832613537376633663032633239323437326536323761306164633534509e070000000000210
        0000000000000ff787e67da7efcb894d5645e9c39dff92c55b03521442837adaadd14501d35ec04da0000000000000000000000000000005cf27
        1797c338547d3a1b1388ca2c5ca918f3937d5a8eef2ec05fd31fc64793a7e00819da055ded70ce982078f52126cc68eade3c1fd0cb2fbd85e9e
        1b6214128a000000000000003063373636366465383631363637306364323437653434303439613530343031303464653332363764323765646
        43134363831373336633230613439633162343339373830376230613230643034633763366461336664353432613762643966316561373734323
        936666231663463323334336466396663376538336466636535653434386531613231d8ac0700000000002100000000000000ff787e67da7efcb
        894d5645e9c39dff92c55b03521442837adaadd14501d35ec02da000000000000000000000000000000bcabbeb4aa12e51d6b9b58c7608353130
        4574486326c18c8b3d8cca874bdff143e80ddf68f6a5a5fe34bc8c48cf5eaf8f0b3505f4269990fa324584df6a8715f8a0000000000000030633
        23638396431313661663030366232326664663361623638386665363839366534373363363066316331663963636433356264353531373432616
        43139333061623239383664613738626239333266303965313236343532646133373830366566336664336665363832323931323261353335653
        764646463316262343637653332383834363033d8ac0700000000002100000000000000ff787e67da7efcb894d5645e9c39dff92c55b03521442
        837adaadd14501d35ec00da0000000000000000000000000000008e49dea24a54a622cc2f41e00012c5cb4534dd4926b88a86286ca57314f0001
        8042124e2e553e410ca330d656ca519bc980d60801cbe82cbf6b94fc4a522d64f8a0000000000000030633563326235616136663534316565306
        63434646234313435356565666464316564313131396134666136356237373661303565373539623036346431353030633136666433396564333
        73333323930643663323866353036346134363163663937656335323430313030343737353161383030383137383734613634613636356465623838653865d8ac0700000000002100000000000000f5fb010baeed21542d3c8bd1ff08ba7b57c5558d3834006a172c33c834e89f6806da0000000000000000000000000000003cbb16aa82cef8e147dd54532511f6845515b3807a60197d50a2db8b1785a27e22120b1b1f119c2be786c59981ed5ee5973f33172ef8d2c48d5fca6ee65b51238a000000000000003063366138306664386330306134336330323935353139306535616534383532303134306233333432356534646233303730653537366161333430366131343133363561346633393366653563346139663561313234343936313663633366643534323264346333643832363234663761353630346432386438663638623732366465623465356135616add0700000000002100000000000000f5fb010baeed21542d3c8bd1ff08ba7b57c5558d3834006a172c33c834e89f6802da0000000000000000000000000000000ac86ef15579a93c8ca955ab81c5cd88506b2bf339015e96ed04799c4b358b01f0e3f717ff05944b872f95acc65b1e03e0c7c69d0cca664757bcbe94a5daa0058a000000000000003063313461643534626235333737383336383466363464313564633837333436653165643139366639353733353064373936363164626432356332613038306430623830646234333132636131376566636439376638356664353861306434366565373932633164343433633563663063636561613333666662616639646638323764633232303461336add0700000000002100000000000000f5fb010baeed21542d3c8bd1ff08ba7b57c5558d3834006a172c33c834e89f6804da000000000000000000000000000000d8fe7b31360a56f1e336a01cab9048f8c609071d096ac2984bc66a938a41e03c86dd60fd41c67434edc4bffee075edd4528b50bea82fb85eaf19d1c8dcc9df728a000000000000003063343864333261316436323263643364303232366164323766326438626331343061393936653031333838316563353730316139336365656562363262656633353432366132346632636262623866633230316238613131333536336466653562633639393261643739613164353066393966333636393264376161363361346237333030666463376add0700000000002100000000000000b06381223006e33a533c5f9180f31a838e10f6c95c307881b163ac51d875b5f506da000000000000000000000000000000d2de11ce9439a23ce250292821016d15edeaf5a7235e3d6fb28ee5601cf1836076d7c52504e59dc95875576fede75166637e375a9b2319396d0db76f4d419b5d8a00000000000000306336653539386632663666393134343234356362353235333532326438643734353036646139653535663438336333326232383565613132343763386361363634313234323834366361383565383364643762326235376261643165376336373362336234373338323862396662373764356261623033653564626465386632633963663834653264bcc20800000000002100000000000000b06381223006e33a533c5f9180f31a838e10f6c95c307881b163ac51d875b5f500da000000000000000000000000000000243ba25b9e5ff97174cafff4460cf0a3fa2ac7e942c1723f66308bfa8509394472262929226a06c324a7af4cb8c46d1e5449ecac5262d3843f7138dfd6351a298a00000000000000306362366339663065383938663731643631636530636430613137393337333561356231616437383261633162306431653535383362333134306339633331373336353637346637346230636436383965306435336161636633313261346165333830383863343564666563353865623731313466653230616332323965346134313561663361396565bcc20800000000002100000000000000b06381223006e33a533c5f9180f31a838e10f6c95c307881b163ac51d875b5f504da0000000000000000000000000000001c9dae298cc16e2cc415a25271c5da7db8abae647464b4917f774147021d1c12803459cc3ad45e74f30bd2f3a142269773d7edb98020777e60634b8ba7c2345b8a00000000000000306337653636613162383931336563663561393166316463313164343032313935353738613230313232333532333738323531633232623766393731333563313462393832396162643231396537643231316536313864326464343538643664613261353761613730343033333839383131363630303861393531353764303334366163323839373064bcc20800000000002100000000000000e6a124f06155fa5b289ed125bd7ffcf53c366ccdf0f90033f4278533e53101c301da0000000000000000000000000000002c987954494263b6be15de657679c8ea4c4ae5436659eab7b0f3eb88f6e6ec514631818324e37f4f30c68622dbe2ddbb7903ccbbc1ac080bbdfa2819c4013c718a0000000000000030633230346164623337373064643864393466323464633536613364366162636438323138633162653263336666353365333365316339343961366436616632306362613862306532383938366464616361393633333937643037393165343936326330636236613235633335353835656163393262323664386337613761323530393239326532633965c30800000000002100000000000000e6a124f06155fa5b289ed125bd7ffcf53c366ccdf0f90033f4278533e53101c302da000000000000000000000000000000189755a63403d89f43073928b7204c626a446e9d2bae5067651b7813511c88148c438c31b71f46bc326093a351198c2d9ff3c60fa0fb209a0823449673ce96148a0000000000000030636138623630643430366665653037616236616635366236616639626638386262396562643063373331393339306236303432626665656238643138316438326130613237376466306230613832363561633565353231393364353936306266363765643037323730653233386136363863353464336465326632333231613038313038326133646665c30800000000002100000000000000e6a124f06155fa5b289ed125bd7ffcf53c366ccdf0f90033f4278533e53101c303da00000000000000000000000000000026004cb0a00a0380ab74adb0888994295edaf96e6e578457e7b7cecd5a03e22bce551ed08abd1fe26e6403f23ff8f6ddc9b16e623cf08a5c8feba7d72bebaa008a0000000000000030633965613263623462633738376263303632643166623462323531333637623134386532656330346362376631316338646533333161653366383966623330323836346536363137633638663533616636326665326233633631613436616439313539303730613238323435333035643066663864326565313437616533333738613831303465336165c30800000000002100000000000000e6a124f06155fa5b289ed125bd7ffcf53c366ccdf0f90033f4278533e53101c304da000000000000000000000000000000400e6323889fe3c43c77547807c84faa6ebbf43cf11cda40581533155844fc7026a5223668e00a0356a7727a25a832424c8b111e662cd092908005e5e9fb99718a0000000000000030636534633534393633306130613065356231393737373337343932316263316238653938346433386136653934343362373435356630353265393634316263356431323132663264323461626335653930323839383765323062653431303634386663363563356239633563323264636263343363626662643535643363313336313635633732313665c30800000000002100000000000000e6a124f06155fa5b289ed125bd7ffcf53c366ccdf0f90033f4278533e53101c305da00000000000000000000000000000022b5bbcde32bb746486bd2f0c453695dfa27a95a98ddeff1af9b586f4ada354728bb9d87cdecd8c72d91f4d4b0faed91e5ae112ee7ab96fd861850b61460030e8a0000000000000030633538326562666234333235343531306266393838373263363538336335313434633463643061623934383733356265643835663137383332373161633963373066383832633561653039383338373432376232343461303963656466376563326436343365666330383336373239643839373837393165353832343232373033353539353237333765c30800000000002100000000000000e6a124f06155fa5b289ed125bd7ffcf53c366ccdf0f90033f4278533e53101c306da000000000000000000000000000000085006667f817bb02ede447bbd6a3b90e8f23ed97dc23ce3d657040695fbca2884a7ffd2b3cd0433d441f87138e670b1fa2c9013e947dc81be4b84e689a592358a0000000000000030633530626431356363643339613134343939303861613031613961333938353239386564633437383865633131356561663563393162633663633137346231376262613833653232386431333766313961386639653030363162373033323962656466353933643734636130633363383731376436366264623538643437653135313739396332396365c30800000000002100000000000000e6a124f06155fa5b289ed125bd7ffcf53c366cdf0f90033f4278533e53101c308da000000000000000000000000000000dc2180c3304f1ec8b1ec0ce9b3d
        2a3ccde4e65b10076d17e2f523d86ec21dd38eadf7ee662123c7a9db1b724d529eb5b6663cad9bf124dfa4f93445ba26af45d8a0000000000000030636232666438633131386231313835666331646262363061613235333635303163623337333730663332376233346538623432386233356138383734343030346261306334303433623437326333663663323039663530326662353231616537303538666364363061656165383032353930323437383931656132393132343764393462666434643765c3080000000000210000000000000009fa138b009a97572194b973449694d975b357c2fca451f0dffd8efc88c8b13800da0000000000000000000000000000004a7532e4641ef77403e0c5b193fa9a436329b63bb9ebcd14706d56ed8b619b7f3482e37a89af5203a8a8569caf8db3d4c5fbe3813a8fc69338c660d2bb9659128a000000000000003063623261663839613066336661306234306662653662383162386562646634663637343530613763623237323465376238343730363465323765646531313231313838326437396635393466626139656139626264663432333661643234633464646533663334326536383361336131623161623832633138336234623434353863613633633031621fcf0800000000002100000000000000cb58e04b5608e531803d6925319052c70167b73fac46c1e5220330830ac21d3d00da000000000000000000000000000000e83b1e787e037a8607d556db75831649ebcbc8be6934ca628b4a1fe4192a4932c4f11b02e076cd8c87e3b28c99c6e50d41c9c11b5b34138dc78b6831aa3b38438a0000000000000030636465396266353238363233303532633864633733366434326636653262643038656130613530663034653834613934316633396630326231393664393637343736366637306438623930313366383965353538353765363432386464663562663736353066643632663930623336643938303935646634633438356231633535303835333665613097cf0800000000002100000000000000ee45321d97df59c4701e37328f6ae1b918973bc7b9022de3856c733765480d0400da000000000000000000000000000000184d925b143c56dff228c6e00c40077f162116283647aadd7b006a8218b9dd74bc140cf8f2e6e1cde9072f5542d572a97dd0bc2c25106fde778b0fa2476acc128a00000000000000306337363631393263303865666564323033613562373536326132336362666636343035363562643730333132306162373336643339333239383834636130643765386332356536613836633234376532663438323862383431623262633232353265346234383662306466633863363162666238653037373732323832616530313239363664376266a2cf0800000000002100000000000000ee45321d97df59c4701e37328f6ae1b918973bc7b9022de3856c733765480d0402da000000000000000000000000000000bedc2376c000f9181155820c31d08b72e9d9ed4e463fff15537f077d597bee7a2e7a37351171f3f24d66abe0a48e42d80dcc2e19ecf07ccfc4932d8001059d7e8a00000000000000306337653937376561623962336230663161663163333930366162623164633935366661663064663839366437356366393930383530363361656164373038363237373066643839383938633966353264613465313239313832336139353566383938633366383033646433656562386631326162646465316235653662663535656434383336613861a2cf0800000000002100000000000000ee45321d97df59c4701e37328f6ae1b918973bc7b9022de3856c733765480d0404da00000000000000000000000000000030425d2f6654deed104f67d63471fabcfb861379f2d31fc7cad4beef52b8d86b500f4d69f65e1ca995081f2bdefd8a0b4577dd42bb47582da18c112941aec0198a00000000000000306338323930666638626664396636366565383632353864313262313665313164376663313238313136323738303535316438363066393764633735323263653131306537653035363865663939386339326239396135623339646335613332373736316661343531666164353937633938303064623261646664373433393533343764383937386162a2cf0800000000002100000000000000ee45321d97df59c4701e37328f6ae1b918973bc7b9022de3856c733765480d0406da00000000000000000000000000000094820d2a761f15949c88e0b457e2f78af6ef9e13da98b667fb8c081aaedf220fb2a857171ebfa6e8f840a21461370b5286057e3cae12cba1c8f430dd0fa354008a00000000000000306331343036653938353237386235643439666661393739663862363638373033333430633761313433363030366432343765626436653464386535353535623361663030393164313033653335366361613730643137653365376561343233336133376639653765633265666266393539356230656661343737326236336337653439316331373961a2cf0800000000002100000000000000ee45321d97df59c4701e37328f6ae1b918973bc7b9022de3856c733765480d0407da000000000000000000000000000000d8f14fa6d5943b02d71c13d106b7cb1200465e71ee3e88303e239bb30eda5138806ebb6641b2d689c9b1325f456e01e9fafa0f8f7ecaa175226188009f6914208a00000000000000306338616562356266643238623864666566303033353630663965343264333135353937663263623637633738313730616135646165633365616333303235343566646333613930633463303835643137666332303136333633363438333666316436386334366538356165616566313331363132393034366333383835626335376162303361356265a2cf0800000000002100000000000000ee45321d97df59c4701e37328f6ae1b918973bc7b9022de3856c733765480d0408da000000000000000000000000000000766de3a497519d2175184016389ea94c4590e7a1950e0ed5632f4282c1d46c61bec61c28522744e40d4e4803c71dfea184c36d062a38b08cb2a67fa8e870d4568a00000000000000306361363361353361623430376462653935326133313934383962653566376337643636343264396639656336373735303032356461353937313337626436613132333435393835616330646338653462623233336163366262623234656264613330356562653234613933613934343337613762323433303965353063303636326466366163323230a2cf080000000000210000000000000069cbbd543c5135d82ee16b92de40662f98a4f6628d561c10803991f3eebd120500da0000000000000000000000000000003aa8b18a8d0f5646a29d892c5bcc04387874d0ed3b5ec0599408858bc539666bec251af372283b3843dacbc06000f5e667166f9ae0f473440ab3cb44c63fe0648a0000000000000030633738653637663632306536626234303766616532613332376438646461363461323237373932346165393930383361323938373139656164363731613565353839306266616161613965383363336462353033353865613237343439396434653162323433393639626336323639366364366135653838636237356133633432356332396461666128d108000000000021000000000000001b3a2116f630f8abe79f13459d8e35220812f42d39ee823511db894f5aacd43800da0000000000000000000000000000000cdbcc31d9945a2016e9c986f93ca299ef8a4e5173f5025a9edcef4398d57c3d1a4e3cf36c6e1819373eb86277e522c19ccfc74a86d465b9a1c678baf07cc87a8a0000000000000030636632616461383835636337633862356164396333353265323866373738373961626134363637343235646237613732353236303261353932396633313630376463633438393036346538323232373561396336643532346466306234333730303066373530346561323337633631343034366661333966666134356331323537326266656531356477d10800000000002100000000000000427394f4ef5421cd8b3b30c05b29ba51f01912ee96fd805b516e00cedae85ccf00da0000000000000000000000000000005cd4c04d70d11b8201b11197aa9c7943bc4928ec130484e8c0aa19c2ff601e2548f056d4895ea5a8a7b8fd445ad83cf8c80d1ce5eae72eaee512b501828e6d318a000000000000003063646530363331336332373736653832653631656130313233326564326438623462343036653361386537646163323930663266373434633938353838343231373830393031626132393764626165376364303730383538653130326638623165333563666661376434666532666635336131306436653532646562626262363739343862333233318ed10800000000002100000000000000692e9948dc920652291dedc64e8260cda89270cbbbef1a6361d3dfcdcfb9b20300da000000000000000000000000000000e6723f2f7cdba8e78280a16abe1d79434c17728d3c3da42b8a5e7e7e14a0584f169d9d13c88d76ae5361e25d5b0570873e42fe1565f5ecee2f456f2fbe11a07f8a0000000000000030633132616135356238623036393738376636636532333834653365616664666139336331366636336638656564623966306235343337346262316238653136346361306536323363393736306432633664
        6236646330343536343964626266646530613565653031616637323061323433643033366632306561616266323836656264333931626437b0d108000000000021000000000000001d5be2146ef28437853d2d2bacf6d7daa55e532115d239a57de6247ef855e4fd00da000000000000000000000000000000823dc0de177ae8ed422ebca9cd91c8e1235146cd572402e32bd56134f060b5112e94f02d0023eb7f65eee08c851a2bdb8728b8d09ef704b1b38a9f62f94965258a000000000000003063636164373734356235333036633534653361343333653632323662373539363763383338656465616233343737316661326432316530616465396638323330386634366439326561326438386566343164373830656462633036616133366535623765363635386638663134336238346131656234316536363439393232343864353338346133651fd2080000000000210000000000000040313d79da9a4e7ca5abc269f4952f2ebb072b5c2fd2abb1552675ca577e7d1e00da0000000000000000000000000000009c48a67fd954ce4ec52332d4be879d1f69add62c0b306deb219de9eba0142122d4b68c7521414574990883062e62413f099d0189fb1c5181ab3666a3e0b6d4438a0000000000000030636236333761393238346636643164383532346363343937626437616664333233383238633230623734653961383836353064636331313134613131663836353734346462623733666135303564643663626131643462306632663561336463343535653862633634663036383234333964326139333035303562353738633131643536306365363551d2080000000000210000000000000043a4cfa0a77544e53078cb3f6c44b63e24e81c4c5e011272e369c32fe890868108da000000000000000000000000000000984f78ab95948e760f1ab96695275eecc84fd1cfc01105c8cdab363099cf747fe42953cf3a34ffff48cec9e6e0ec7af6edf16386c29517598b0aa7fc3e2b8d358a0000000000000030633963366535636534336637323137613366313930353063643163323766656330613063333635616637353665636264633434326265386563393636376636373136653633303437313331636161393839303732333931386230633566636166303839343737336638363165643039363036306264353834313761323539323634613062373236383688d3080000000000210000000000000043a4cfa0a77544e53078cb3f6c44b63e24e81c4c5e011272e369c32fe890868106da000000000000000000000000000000ac7454eaf892cdb01145303a3266af0b3cdd138756a6860e9868163e3733b6369e33c3b97cc3925dcd9002ed772ecc1bae1aeb30fb6fbd6625d05a5a22d7b36f8a0000000000000030636438663936613031343434313261306532346133623339646437346136373430336564386338343266323035373863393964356463353933636563396333336361383232366334393638616263326237366131396662613462343934323938656438626636626636383563663965333164663034333031363439623362643134373232343134303888d3080000000000210000000000000043a4cfa0a77544e53078cb3f6c44b63e24e81c4c5e011272e369c32fe890868104da000000000000000000000000000000583c88ff652e67e16ff5cb7e241351038c58363799c9407e12f39e1853d9c9390616e37855ddf868ff1fe07ad1a2ea73f1001f38ce34e842bfa932a3cd0be87f8a0000000000000030633638363462366462666365653963313338363837623961633632633064353432373065333361326465326266323434343265353532626532383064393030323434303039666664643636313737303235343639613232396462323064633538663665646631313033643466346164396163386332376137633564313339653566313434343762653088d3080000000000210000000000000043a4cfa0a77544e53078cb3f6c44b63e24e81c4c5e011272e369c32fe890868103da0000000000000000000000000000002899b23e5cf11c8a23a2f0e62626c1833e42c114a9471e0393d90c719bd611398c1081e742bbfbd98483d98b70e552c67cbf579bc2d360068ddcb5ad2158ca688a0000000000000030636434623634646233323163356365366438373965643431313665353331353833333761346165333966313937396533323135653866343762376337333335303966326132343235323737363339326165303736646566623835366536643161646238393739656538363563613632343762366132303030383931373363313131653736373564363188d3080000000000210000000000000043a4cfa0a77544e53078cb3f6c44b63e24e81c4c5e011272e369c32fe890868101da000000000000000000000000000000f6e74ab71744d8822b29c46fe1347a90ef52c3ba7ddcf0edad32a97a271f80526e3cf1cd883d24d1f0eeb90b98b93ee1147747b686eaac9cdc48001db52d384d8a0000000000000030633734303936393538346337663866663561396566646362363838363434653365323632313865613938363936643039663662613966393239653136666466363938383766646165363634316233613038346461376539343335666531653664653238623464656231653832346566333964643238653464366566366138663233356663313034623788d3080000000000210000000000000043a4cfa0a77544e53078cb3f6c44b63e24e81c4c5e011272e369c32fe890868100da00000000000000000000000000000046c3e54d38a7b8f6a6ca208e911f224ff5aa9f6009ebf4e94ed30ec466649411bc0d0919e1b641bbd2200bf9544a0f621b593677288ce4570e09062d4554fc1c8a0000000000000030633265666465356237353837326465306130323731373538633064653164636335646330653864383763396336623736623037646330643233316330653138326663323831613162333165346463623837363065623233333932373031633938373633303262393138663935353830336136333864333634623134303464323063353466353163653188d3080000000000210000000000000043a4cfa0a77544e53078cb3f6c44b63e24e81c4c5e011272e369c32fe890868107da000000000000000000000000000000a60da5291145f5feaf1cea582e37196c12b02afc64650e80bb57db2f822f7a3b527e445fd50fcff5ae5224e3cdccbabf88745c1ddf82fae92552cf21346680718a0000000000000030636163393364376535323231653137363933306139343036626165653637343465656564643232393063623963336438356539363836303665666337616562353764363037383330316666396435326437343631643462336463316131353365323036323665393166613462646162363561316530363231373461623533353030623963346231396688d308000000000021000000000000007523f0ae08cf849fc2929286ec89e619a01912beec35245be8936d9d8bd6595901da00000000000000000000000000000098721ffac99adaae49feec3a7398d9f2379c1b565c2453df3d69a53fb41134052e0fdf67dd6c78f679b755f17f8954ba9fcd5240c49aab12753bcf6b9712851e8a00000000000000306365636465376431666430336435633335643937353566663964636363663232383361613333353139383166663362313638396336363238393063616135303661306133396561393761656565303533306133326134346232303236333935323461366233376433353466326339636463343939653563616339326363616237623333663133646561a3d508000000000021000000000000007523f0ae08cf849fc2929286ec89e619a01912beec35245be8936d9d8bd6595900da000000000000000000000000000000a66af373fc5d4927a8bf217d245a8328b04e1c840d00938c25025257bb0f7f135a183b729259e341c8a01cc8201a428c71ac791bcda61a2697f3b65688ce211d8a00000000000000306366363431626433356137653834623336333235313233303030333838336634346663333465343639393363326139306636383062373664316464663837383531353263306335666266633861613930626263356430643464313830326630376364316139343765633530303531346262383261336465343166353632613037333733343466303161a3d508000000000021000000000000001bc3445f665e5cc65cbf69a3812de946db69d70ad558d48fd4de1c61607a695500da000000000000000000000000000000580e8df03d18e36cc8699bae0e0fe740ea3356a758de27a3e03bfe9d428ddb483af999cfff5b83ab15ff2f17f95686a1bb2c0bdd94badf14effb0df5f45b16318a00000000000000306362636537613634306139393861633536343537626137386562613336363534666330396364333561626433363939636335663665636138383765323835313533356365393564373037383335356633323831616633633261383530343731636538363935613962363731393233643431396130383066663666363735363136346638316538353330b3d508000000000021000000000000001bc3445f665e5cc65cbf69a3812de946db69d70ad558d48fd4de1c61607a695501da0000000000000000000000000000003e9a95c4fcc7765aaa2081f2f702a4313957dbdaadcc7bb831a2290e1c44205558744b0142348bd4e70497b97e13b306d551b6a61304767ec27972eb7b5de5408a00000000000000306338363037613833626365613864313265316164663332613430663562633830336133323736623639663433636330373534363635333432633737323162353062323664303665336365386536643531336665373337613233336336353733613164366262323334656466363030633161613838656265383831643366393033336638303833643866b3d5080000000000";
        let db_str = db_data.to_string();
        let seed = "waaVXJnXIYQd2BG4rVA12q5OTuctzcDt7BLyHw7Yx/1b2iDFrl4kOcC/VlvE3tvLZq7Dd/qSiMEdYK1DvDPmZw==";

        //let addresses = crate::coin_addrerss_monitoring(db_str, seed).unwrap();
        //println!("addresses {:?}", addresses);
        let json_string = r#"{
        "out_type": "Coin",
        "output": {
            "Coin": {
                "encrypt": {
                    "c": [
                        52,
                        23,
                        206,
                        62,
                        63,
                        253,
                        13,
                        228,
                        55,
                        154,
                        95,
                        246,
                        226,
                        183,
                        182,
                        228,
                        85,
                        0,
                        39,
                        224,
                        114,
                        225,
                        198,
                        93,
                        134,
                        155,
                        155,
                        20,
                        8,
                        182,
                        113,
                        94
                    ],
                    "d": [
                        118,
                        155,
                        18,
                        110,
                        81,
                        166,
                        44,
                        185,
                        71,
                        48,
                        248,
                        24,
                        36,
                        220,
                        93,
                        200,
                        158,
                        71,
                        54,
                        79,
                        174,
                        92,
                        36,
                        212,
                        156,
                        59,
                        228,
                        12,
                        91,
                        94,
                        157,
                        7
                    ]
                },
                "owner": "0c665a51d8704b9db5c348cdea2579be030ab182805b084f884e71290c6d298d56422d3364264958db1aba778763fbad5a9762ed53a2aff69c84c6ebfc415ba603f01b9c9f"
            }
        }
    }"#;
        let output: Output = serde_json::from_str(json_string).unwrap();
        println!("output {:?}", output);

        let account = output.to_quisquis_account().unwrap();
        // convert accoount to json
        let account_json = serde_json::to_string(&account).unwrap();
        let verify = account::verify_keypair_account(seed, account_json).unwrap();
        print!("verify {:?}", verify);

        //let utxo_str = "{b06381223006e33a533c5f9180f31a838e10f6c95c307881b163ac51d875b5f500}";
        //let utxo = crate::create_utxo_from_hex_string(utxo_str.to_string()).unwrap();
        //println!()
    }
    #[test]
    fn check_encyprt_scalar() {
        let account_str = "0c1c6835f0475475d388b761ecdc3187890048fed0ffc906751c415d55f792c0288a8a8d0617d2c9291783f0cba0d9f859df00082e70708cbda69ed383a059d109e623a6a83a9095bf4e2bc3d74935b25a2929c43bf18727843eebd5af3bb2fbd19f36696020626e93840ad8bbfeb40ac36c515c4e395ecbaa41eb771f249e2dc4f0bd7442".to_string();
        let scalar_str =
            "d6b956f7c5bbbe7b8ad53a25aa475b5596da34f2f689e91c5b92ddc38fc8e109".to_string();
        let account = ZkAccount::from_hex_str(account_str).unwrap();
        let scalar = convert_hex_scalar_to_json(scalar_str).unwrap();
        let scal: Scalar = serde_json::from_str(&scalar).unwrap();

        let acc: Account = ZkAccount::into(account.clone());
        let (pk, enc) = acc.get_account();
        // create commitment with new scalar
        let enc_new = ElGamalCommitment::generate_commitment(&pk, scal, Scalar::from(1u64));
        assert_eq!(enc_new, enc);
    }

    #[test]
    fn test_public_key_from_hex_address() {
        let hex_adress = "0c74c272bc85676a28c60c12d173cb513cb7e89a34e9e647e6a77ca4a2e55e696d88d061cb60ed1a69dbb26c133f04b1549021109039f7f7aff8b3d4cc9df1ce24e4bab664";
        let hex_json = serde_json::to_string(&hex_adress);
        println!("Json = {:?}", hex_json);
    }
}
