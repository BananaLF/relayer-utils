use anyhow::Error;
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
use serde::{Serialize, Deserialize};
use serde_json;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping from the
// current local frame (which is the scope within which local (temporary)
// references to Java objects remain valid)
use jni::objects::{ JClass, JString};

#[derive(Serialize, Deserialize)]
pub struct JavaResponse {
    pub code: u8,
    pub msg: String,
    pub email_auth_input: Option<String>,
}

impl JavaResponse {
   pub fn error_response(errmsg: &str,err:Error) -> Self {
        JavaResponse {
            code: 1,
            msg: format!("err_msg: {} reason:{}",errmsg,err.to_string()),
            email_auth_input: None,
        }
    }

    pub fn success_response(input: &str) -> Self {
        JavaResponse {
            code: 0,
            msg: "success generate email input".to_string(),
            email_auth_input: Some(input.to_string()),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
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
pub extern "system" fn Java_ZKEmail_generateEmailInput<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    email: JString<'local>,
    account_code: JString<'local>,
) -> JString<'local> {
    let email:String = match env.get_string(&email) {
        Ok(str) => {
            str.into()
        },
        Err(e) => {
            let output = env.new_string(JavaResponse::error_response("can not got email from input",e.into()).to_json()).expect("Couldn't create java string!");
            return output;
        },
    };

    let account_code = match env.get_string(&account_code) {
        Ok(str) => {
            let code:String = str.into();
            match hex2field(&code)  {
                Ok(code) => {
                    AccountCode::from(code)
                },
                Err(e) => {
                    let output = env.new_string(JavaResponse::error_response("account is wrong value",e).to_json()).expect("Couldn't create java string!");
                    return output;
                },
            }

        },
        Err(e) => {
            let output = env.new_string(JavaResponse::error_response("can not got account code from input",e.into()).to_json()).expect("Couldn't create java string!");
            return output;
        },
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    // block generate_email_auth_input
    let result = match rt.block_on(generate_email_auth_input(email.as_str(), &account_code)) {
        Ok(result) => {
            let output = env.new_string(JavaResponse::success_response(result.as_str()).to_json()).expect("Couldn't create java string!");
            output
        },
        Err(e) => {
            let output = env.new_string(JavaResponse::error_response("account is wrong value",e).to_json()).expect("Couldn't create java string!");
            output
        },
    };
    result
}




