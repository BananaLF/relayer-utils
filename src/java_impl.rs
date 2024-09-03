use anyhow::{Result};
use crate::{AccountCode, AccountSalt, circuit, email_nullifier, EmailAuthInput, field2hex, hex2field, PaddedEmailAddr, ParsedEmail, public_key_hash, vec_u8_to_bigint};

pub async fn generate_email_auth_input_for_java(email: &str, account_code: &AccountCode) -> Result<String> {
    let parsed_email = ParsedEmail::new_from_raw_email(&email).await?;
    let circuit_input_params = circuit::CircuitInputParams::new(
        vec![],
        parsed_email.canonicalized_header.as_bytes().to_vec(),
        "".to_string(),
        vec_u8_to_bigint(parsed_email.clone().signature),
        vec_u8_to_bigint(parsed_email.clone().public_key),
        None,
        Some(1024),
        Some(64),
        Some(true),
    );
    let email_circuit_inputs = circuit::generate_circuit_inputs(circuit_input_params);

    let from_addr_idx = parsed_email.get_from_addr_idxes().unwrap().0;
    let domain_idx = parsed_email.get_email_domain_idxes().unwrap().0;
    let subject_idx = match parsed_email.get_subject_all_idxes() {
        Ok(indexes) => {
            indexes.0
        },
        Err(e) => {
            return Err(e);
        },
    };
    let mut address_idx = match parsed_email.get_address_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };

    let mut pubkey_idx = match parsed_email.get_pubkey_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };

    let mut validator_idx = match parsed_email.get_validator_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };

    address_idx = address_idx - subject_idx;
    pubkey_idx = pubkey_idx - subject_idx;
    validator_idx = validator_idx - subject_idx;
    let mut timestamp_idx = match parsed_email.get_timestamp_idxes()  {
        Ok(indexes) => {
            indexes.0
        },
        Err(_) => 0,
    };
    timestamp_idx = timestamp_idx - subject_idx;
    //println!("{}",parsed_email.canonicalized_header.escape_default());
    let email_auth_input = EmailAuthInput {
        padded_header: email_circuit_inputs.in_padded,
        public_key: email_circuit_inputs.pubkey,
        signature: email_circuit_inputs.signature,
        padded_header_len: email_circuit_inputs.in_len_padded_bytes,
        account_code: field2hex(&account_code.0),
        from_addr_idx: from_addr_idx,
        subject_idx: subject_idx,
        domain_idx: domain_idx,
        timestamp_idx: timestamp_idx,
        address_idx: address_idx,
        pubkey_idx: pubkey_idx,
        validator_idx:validator_idx,
    };

    Ok(serde_json::to_string(&email_auth_input)?)
}

pub fn generate_email_nullifier_for_java(mut signature: Vec<u8>) -> Result<String> {
    signature.reverse();
    let nullifier = match email_nullifier(&signature) {
        Ok(nullifier) => {
            field2hex(&nullifier)
        },
        Err(e) => {
            return Err(anyhow::anyhow!(format!(
                "email_nullifier compute failed {}",
                e
            )));
        },
    };
    Ok(nullifier)
}

pub fn generate_publickey_hash_for_java(publickey: &str) -> Result<String> {
    let mut publickey = match hex::decode(&publickey[2..]) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err(anyhow::anyhow!(format!(
                "the input string {} is invalid hex: {}",
                &publickey, e
            )));
        },
    };
    publickey.reverse();
    let publickey = match public_key_hash(&publickey) {
        Ok(publickey) => {
            field2hex(&publickey)
        },
        Err(e) => {
            return Err(anyhow::anyhow!(format!(
                "email_nullifier compute failed {}",
                e
            )));
        },
    };
    Ok(publickey)
}

pub fn generate_email_hash_for_java(email_addr: &str,account_code_str: &str) -> Result<String> {
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let account_code = hex2field(account_code_str)?;
    let account_salt = match AccountSalt::new(&padded_email_addr, AccountCode(account_code)) {
        Ok(account_salt) => account_salt,
        Err(e) => {
            return Err(anyhow::anyhow!(format!("AccountSalt failed: {}", e)));
        },
    };
    let account_salt_str = field2hex(&account_salt.0);
    Ok(account_salt_str)
}