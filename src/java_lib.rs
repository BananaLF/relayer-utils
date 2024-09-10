use std::any::Any;
use std::panic;
use anyhow::{anyhow, Error};
// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

pub use crate::circuit::*;
pub use crate::converters::*;
pub use crate::cryptos::*;
pub use crate::logger::*;
pub use crate::parse_email::*;
pub use crate::regex::*;
pub use crate::statics::*;
use crate::java_impl::*;
use serde::{Deserialize, Serialize};
use serde_json;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping from the
// current local frame (which is the scope within which local (temporary)
// references to Java objects remain valid)
use jni::objects::{JByteArray, JClass, JString};


#[derive(Serialize, Deserialize)]
pub struct JavaResponse {
    pub code: u8,
    pub msg: String,
    pub data: Option<String>,
}

impl JavaResponse {
    pub fn error_response(errmsg: &str, err: Error) -> Self {
        JavaResponse {
            code: 1,
            msg: format!("err_msg: {} reason:{}", errmsg, err.to_string()),
            data: None,
        }
    }

    pub fn success_response(input: &str) -> Self {
        JavaResponse {
            code: 0,
            msg: "rust call success".to_string(),
            data: Some(input.to_string()),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

fn box_to_anyhow_error(b: Box<dyn Any + Send>) -> Error {
    if let Some(s) = b.downcast_ref::<&str>() {
        anyhow!("{}", s)
    } else if let Some(s) = b.downcast_ref::<String>() {
        anyhow!("{}", s)
    } else {
        anyhow!("Unknown panic payload")
    }
}

// This `#[no_mangle]` keeps rust from "mangling" the name and making it unique
// for this crate. The name follow a strict naming convention so that the
// JNI implementation will be able to automatically find the implementation
// of a native method based on its name.
//
// The `'local` lifetime here represents the local frame within which any local
// (temporary) references to Java objects will remain valid.
//
// It's usually not necessary to explicitly name the `'local` input lifetimes but
// in this case we want to return a reference and show the compiler what
// local frame lifetime it is associated with.
//
// Alternatively we could instead return the `jni::sys::jstring` type instead
// which would represent the same thing as a raw pointer, without any lifetime,
// and at the end use `.into_raw()` to convert a local reference with a lifetime
// into a raw pointer.
#[no_mangle]
pub extern "system" fn Java_com_okcoin_wallet_sa_service_utils_email_ZKRelayerUtils_generateEmailInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    email: JString<'local>,
    account_code: JString<'local>,
) -> JString<'local> {
    let email: String = match env.get_string(&email) {
        Ok(str) => str.into(),
        Err(e) => {
            let output = env
                .new_string(
                    JavaResponse::error_response("can not got email from input", e.into())
                        .to_json(),
                )
                .expect("Couldn't create java string!");
            return output;
        }
    };

    let account_code: String = match env.get_string(&account_code) {
        Ok(str) =>{
            str.into()
        }
        Err(e) => {
            let output = env
                .new_string(
                    JavaResponse::error_response("can not got account code from input", e.into())
                        .to_json(),
                )
                .expect("Couldn't create java string!");
            return output;
        }
    };
    let result = panic::catch_unwind(||{
        let account_code =  hex2field(&account_code).unwrap();
        let account_code= AccountCode::from(account_code);
        let rt = tokio::runtime::Runtime::new().unwrap();
        // block generate_email_auth_input
        let result = rt.block_on(generate_email_auth_input_for_java(email.as_str(), &account_code)).unwrap();
        result
    });
    let result = match result {
        Ok(result) => {
            let output = env
                .new_string(JavaResponse::success_response(result.as_str()).to_json())
                .expect("Couldn't create java string!");
            output
        }
        Err(e) => {
            let panic_message = box_to_anyhow_error(e);
            let output = env
                .new_string(JavaResponse::error_response("account is wrong value", panic_message).to_json())
                .expect("Couldn't create java string!");
            output
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_com_okcoin_wallet_sa_service_utils_email_ZKRelayerUtils_emailnullifer<'local>(
    env: JNIEnv<'local>,
    _class: JClass,
    signature: JByteArray<'local>,
) -> JString<'local> {
    let signature: Vec<u8> = match env.convert_byte_array(&signature) {
        Ok(str) => str.into(),
        Err(e) => {
            let output = env
                .new_string(
                    JavaResponse::error_response("can not got signature", e.into())
                        .to_json(),
                )
                .expect("Couldn't got java signature!");
            return output;
        }
    };
    let result = panic::catch_unwind(||{
        let email_nullifier = generate_email_nullifier_for_java(signature).unwrap();
        email_nullifier
    });
    let result = match result {
        Ok(r) => {
            let output = env
                .new_string(JavaResponse::success_response(r.as_str()).to_json())
                .expect("Couldn't create java string!");
            output
        }
        Err(e) => {
            let panic_message = box_to_anyhow_error(e);
            let output = env
                .new_string(
                    JavaResponse::error_response("generate_email_nullifier failed",panic_message)
                        .to_json(),
                )
                .expect("Couldn't create java string!");
            return output;
        }
    };
    result
}


#[no_mangle]
pub extern "system" fn Java_com_okcoin_wallet_sa_service_utils_email_ZKRelayerUtils_publickeyHash<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    publickey: JString<'local>,
) -> JString<'local> {
    let publickey: String = match env.get_string(&publickey) {
        Ok(str) => str.into(),
        Err(e) => {
            let output = env
                .new_string(
                    JavaResponse::error_response("can not got publickey", e.into())
                        .to_json(),
                )
                .expect("Couldn't got java signature!");
            return output;
        }
    };
    let result = panic::catch_unwind(||{
        let publickey_hash = generate_publickey_hash_for_java(publickey.as_str()).unwrap();
        publickey_hash
    });
    let result = match result {
        Ok(r) => {
            let output = env
                .new_string(JavaResponse::success_response(r.as_str()).to_json())
                .expect("Couldn't create java string!");
            output
        }
        Err(e) => {
            let panic_message = box_to_anyhow_error(e);
            let output = env
                .new_string(
                    JavaResponse::error_response("generate_publickey_hash_for_java failed",panic_message)
                        .to_json(),
                )
                .expect("Couldn't create java string!");
            return output;
        }
    };
    result
}

#[no_mangle]
pub extern "system" fn Java_com_okcoin_wallet_sa_service_utils_email_ZKRelayerUtils_emailHash<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    email_addr: JString<'local>,
    account_code: JString<'local>,
) -> JString<'local> {
    let email_addr: String = match env.get_string(&email_addr) {
        Ok(str) => str.into(),
        Err(e) => {
            let output = env
                .new_string(
                    JavaResponse::error_response("can not got email_addr", e.into())
                        .to_json(),
                )
                .expect("Couldn't got java signature!");
            return output;
        }
    };

    let account_code: String = match env.get_string(&account_code) {
        Ok(str) => str.into(),
        Err(e) => {
            let output = env
                .new_string(
                    JavaResponse::error_response("can not got account_code", e.into())
                        .to_json(),
                )
                .expect("Couldn't got java signature!");
            return output;
        }
    };
    let result = panic::catch_unwind(||{
        let email_hash = generate_email_hash_for_java(email_addr.as_str(),account_code.as_str()).unwrap();
        email_hash
    });
    let result = match result {
        Ok(r) => {
            let output = env
                .new_string(JavaResponse::success_response(r.as_str()).to_json())
                .expect("Couldn't create java string!");
            output
        }
        Err(e) => {
            let panic_message = box_to_anyhow_error(e);
            let output = env
                .new_string(
                    JavaResponse::error_response("generate_email_hash_for_java failed",panic_message)
                        .to_json(),
                )
                .expect("Couldn't create java string!");
            return output;
        }
    };
    result
}