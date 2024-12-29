use crate::{
    circuit, email_nullifier, field2hex, fieldstr2bytes, hex2field, public_key_hash, str2bytes32,
    vec_u8_to_bigint, AccountCode, AccountSalt, EmailAuthInput, PaddedEmailAddr, ParsedEmail,
};
use anyhow::Result;
use serde::Serialize;

pub const PUBDATA_LENGHT: i32 = 17i32;

pub async fn generate_email_auth_input_for_java(
    email: &str,
    account_code: &AccountCode,
) -> Result<String> {
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
        Ok(indexes) => indexes.0,
        Err(e) => {
            return Err(e);
        }
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
    let mut timestamp_idx = match parsed_email.get_timestamp_idxes() {
        Ok(indexes) => indexes.0,
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
        validator_idx: validator_idx,
    };

    Ok(serde_json::to_string(&email_auth_input)?)
}

pub async fn generate_email_auth_input_tron_for_java(
    email: &str,
    account_code: &AccountCode,
) -> Result<String> {
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
        Ok(indexes) => indexes.0,
        Err(e) => {
            return Err(e);
        }
    };
    let mut address_idx = match parsed_email.get_tron_address_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };

    let mut pubkey_idx = match parsed_email.get_pubkey_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };

    let mut validator_idx = match parsed_email.get_tron_validator_idxes() {
        Ok(indexes) => indexes.0,
        Err(_) => 0,
    };

    address_idx = address_idx - subject_idx;
    pubkey_idx = pubkey_idx - subject_idx;
    validator_idx = validator_idx - subject_idx;
    let mut timestamp_idx = match parsed_email.get_timestamp_idxes() {
        Ok(indexes) => indexes.0,
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
        validator_idx: validator_idx,
    };

    Ok(serde_json::to_string(&email_auth_input)?)
}

pub fn generate_email_nullifier_for_java(mut signature: Vec<u8>) -> Result<String> {
    signature.reverse();
    let nullifier = match email_nullifier(&signature) {
        Ok(nullifier) => field2hex(&nullifier),
        Err(e) => {
            return Err(anyhow::anyhow!(format!(
                "email_nullifier compute failed {}",
                e
            )));
        }
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
        }
    };
    publickey.reverse();
    let publickey = match public_key_hash(&publickey) {
        Ok(publickey) => field2hex(&publickey),
        Err(e) => {
            return Err(anyhow::anyhow!(format!(
                "email_nullifier compute failed {}",
                e
            )));
        }
    };
    Ok(publickey)
}

pub fn generate_email_hash_for_java(email_addr: &str, account_code_str: &str) -> Result<String> {
    let padded_email_addr = PaddedEmailAddr::from_email_addr(&email_addr);
    let account_code = hex2field(account_code_str)?;
    let account_salt = match AccountSalt::new(&padded_email_addr, AccountCode(account_code)) {
        Ok(account_salt) => account_salt,
        Err(e) => {
            return Err(anyhow::anyhow!(format!("AccountSalt failed: {}", e)));
        }
    };
    let account_salt_str = field2hex(&account_salt.0);
    Ok(account_salt_str)
}

#[derive(Serialize)]
struct Pubdata {
    domain: String,
    pubkey_hash: String,
    email_nullifier: String,
    email_hash: String,
    eth_address: String,
    validator: String,
    pubkey: String,
    timestamp: String,
}

pub fn decode_pubdata_for_java(pubdata: Vec<String>) -> Result<String> {
    /*
     * pubdata:
     * 0 - 8 domain
     * 9 publicKeyHash
     * 10 emailNullifier
     * 11 emailHash
     * 12 eth_address
     * 13 validator
     * 14 pubkey_bytes_left
     * 15 pubkey_bytes_right
     * 16 timestamp
     */
    // 0 - 8 domain
    let domain_bytes = &pubdata[0..9];
    let domain_convert = fieldstr2bytes(domain_bytes.to_vec(), 255);
    let domain = String::from_utf8(domain_convert)
        .expect("invalid domain")
        .chars()
        .filter(|&c| c != '\u{0000}')
        .collect();
    // 9 publicKeyHash
    let mut temp = str2bytes32(&pubdata[9]);
    temp.reverse();
    let pubkey_hash = hex::encode(temp);
    // 10 emailNullifier
    let mut temp = str2bytes32(&pubdata[10]);
    temp.reverse();
    let email_nullifier = hex::encode(temp);
    // 11 emailHash
    let mut temp = str2bytes32(&pubdata[11]);
    temp.reverse();
    let email_hash = hex::encode(temp);
    // 12 eth_address
    let eth_address = hex::encode(fieldstr2bytes(pubdata[12..13].to_vec(), 20));
    // 13 validator
    let validator = hex::encode(fieldstr2bytes(pubdata[13..14].to_vec(), 20));
    // 14-15 pubkey_bytes
    let pubkey_bytes_left = fieldstr2bytes(pubdata[14..15].to_vec(), 16);
    let pubkey_bytes_right = fieldstr2bytes(pubdata[15..16].to_vec(), 16);
    let pubkey = hex::encode([pubkey_bytes_left, pubkey_bytes_right].concat());
    // 16 timestamp
    let timestamp = pubdata[16].clone();

    let result = &Pubdata {
        domain,
        pubkey_hash,
        email_nullifier,
        email_hash,
        eth_address,
        validator,
        pubkey,
        timestamp,
    };
    Ok(serde_json::to_string(result).expect("result serde json failed"))
}

// tron decode

pub fn decode_pubdata_tron_for_java(pubdata: Vec<String>) -> Result<String> {
    /*
     * pubdata:
     * 0 - 8 domain
     * 9 publicKeyHash
     * 10 emailNullifier
     * 11 emailHash
     * 12 eth_address
     * 13 validator
     * 14 pubkey_bytes_left
     * 15 pubkey_bytes_right
     * 16 timestamp
     */
    // 0 - 8 domain
    let domain_bytes = &pubdata[0..9];
    let domain_convert = fieldstr2bytes(domain_bytes.to_vec(), 255);
    let domain = String::from_utf8(domain_convert)
        .expect("invalid domain")
        .chars()
        .filter(|&c| c != '\u{0000}')
        .collect();
    // 9 publicKeyHash
    let mut temp = str2bytes32(&pubdata[9]);
    temp.reverse();
    let pubkey_hash = hex::encode(temp);
    // 10 emailNullifier
    let mut temp = str2bytes32(&pubdata[10]);
    temp.reverse();
    let email_nullifier = hex::encode(temp);
    // 11 emailHash
    let mut temp = str2bytes32(&pubdata[11]);
    temp.reverse();
    let email_hash = hex::encode(temp);
    // 12 eth_address
    let mut address_bytes = fieldstr2bytes(pubdata[12..13].to_vec(), 25);
    address_bytes.reverse();
    let eth_address = bs58::encode(address_bytes).into_string();
    // 13 validator
    let mut validator_bytes = fieldstr2bytes(pubdata[13..14].to_vec(), 25);
    validator_bytes.reverse();
    let validator = bs58::encode(validator_bytes).into_string();
    // 14-15 pubkey_bytes
    let pubkey_bytes_left = fieldstr2bytes(pubdata[14..15].to_vec(), 16);
    let pubkey_bytes_right = fieldstr2bytes(pubdata[15..16].to_vec(), 16);
    let pubkey = hex::encode([pubkey_bytes_left, pubkey_bytes_right].concat());
    // 16 timestamp
    let timestamp = pubdata[16].clone();

    let result = &Pubdata {
        domain,
        pubkey_hash,
        email_nullifier,
        email_hash,
        eth_address,
        validator,
        pubkey,
        timestamp,
    };
    Ok(serde_json::to_string(result).expect("result serde json failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_pubdata_for_java() {
        let original = &Pubdata {
            domain: "gmail.com".to_string(),
            pubkey_hash: "0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788"
                .to_string(),
            email_nullifier: "12c6fc2aaa42727d176c54ec69426cd627a7c23b24e27b04f417862eca256968"
                .to_string(),
            email_hash: "10241e7b040d1b3bd2bb81e7c8df72a56a6818baf6d836368d01a9718839295a"
                .to_string(),
            eth_address: "01eb9b204cc24c3baee11accc37d253a9c53e92b".to_string(),
            validator: "4838b106fce9647bdf1e7877bf73ce8b0bad5f97".to_string(),
            pubkey: "36415f605504b60cd9110d686c4dacab3e5d4f1ee8ef75ca4e5709d9381e55df".to_string(),
            timestamp: "1725260084".to_string(),
        };
        let pubdata = [
            "2018721414038404820327".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "6632353713085157925504008443078919716322386156160602218536961028046468237192"
                .to_string(),
            "8493207383652490715378251287216535597812624715421107390886599766669628107112"
                .to_string(),
            "7300822440554768645609367769095731068168691871678625160882522321750763055450"
                .to_string(),
            "250689960257754200054025474985292455916166966017".to_string(),
            "864191251542667060224262456867428696580615649352".to_string(),
            "228192632673271878678993831162202243382".to_string(),
            "296859801269246450117816979618985368894".to_string(),
            "1725260084".to_string(),
        ]
        .to_vec();

        let result = decode_pubdata_for_java(pubdata).unwrap();
        // println!(
        //     "original: {}",
        //     serde_json::to_string_pretty(original).unwrap()
        // );
        // println!("result: {}", result);
        // 比较结果
        assert_eq!(serde_json::to_string(original).unwrap(), result);
    }

    #[test]
    fn test_decode_pubdata_tron_for_java() {
        let original = &Pubdata {
            domain: "gmail.com".to_string(),
            pubkey_hash: "0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788"
                .to_string(),
            email_nullifier: "12c6fc2aaa42727d176c54ec69426cd627a7c23b24e27b04f417862eca256968"
                .to_string(),
            email_hash: "10241e7b040d1b3bd2bb81e7c8df72a56a6818baf6d836368d01a9718839295a"
                .to_string(),
            eth_address: "TT5iK8oqGEyRKJAnRwrLSZ4fM5y77F2LNT".to_string(),
            validator: "TFqY5k1nvqYuLbCZmwehxbTFCS1eWKgFSY".to_string(),
            pubkey: "36415f605504b60cd9110d686c4dacab3e5d4f1ee8ef75ca4e5709d9381e55df".to_string(),
            timestamp: "1725260084".to_string(),
        };
        let pubdata = [
            "2018721414038404820327".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "6632353713085157925504008443078919716322386156160602218536961028046468237192"
                .to_string(),
            "8493207383652490715378251287216535597812624715421107390886599766669628107112"
                .to_string(),
            "7300822440554768645609367769095731068168691871678625160882522321750763055450"
                .to_string(),
            "412614185606728529393157974940103532625248938116289359027920".to_string(),
            "409589829848871404927940772198240099290401898606088774721113".to_string(),
            "228192632673271878678993831162202243382".to_string(),
            "296859801269246450117816979618985368894".to_string(),
            "1725260084".to_string(),
        ]
        .to_vec();

        let result = decode_pubdata_tron_for_java(pubdata).unwrap();
        // println!(
        //     "original: {}",
        //     serde_json::to_string_pretty(original).unwrap()
        // );
        //println!("result: {}", result);
        // 比较结果
        assert_eq!(serde_json::to_string(original).unwrap(), result);
    }
}
