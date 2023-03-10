

use sha2::{Sha256};
use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use super::encryption_utilities::*;
use aes_gcm::{
    aead::{generic_array::{GenericArray, typenum::U32}}
};


const PRIVILEGE_KEYWORD_INDEX: usize = 0;
const HMAC_INDEX: usize = 1;
const ENCRYPTED_MESSAGE_INDEX: usize = 2;
const NONCE_INDEX: usize = 3;
const PRIVILEGE_KEYWORD: &str = "Privileged ";

pub fn generate_hmac (key_slice : &[u8], message: &String) -> String {

    type HmacSha256 = Hmac<Sha256>;
    //let mut mac = HmacSha256::new_from_slice(key_slice).expect("HMAC can take key of any size");
    
    let mut mac : HmacSha256 = hmac::Mac::new_from_slice(key_slice).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    let base64_hmac = Base64::encode_string(&code_bytes);

    base64_hmac
}

pub fn verify_mac (key_slice : &[u8], message: &String, base64_encoded_code: &String) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key_slice).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());


    let code_bytes = Base64::decode_vec(base64_encoded_code).unwrap();

    let res = mac.verify_slice(&code_bytes[..]);

    if res.is_ok() {
        return true;
    } else {
        return false;
    }
}

/**
 * Privilege request format:
 * *********************** * *********************** ************************
 *         Privileged     /    hmac(Privileged|cmd|args)     /  encrypted cmd + args / tag
 * ************************ ************************************************
 *                        
 */
pub fn prepare_priviled_exec_cmd(cmd: String, key_slice: &[u8], key: &GenericArray<u8, U32>) -> Vec<String> {

    // println!("cmd before {:?}", cmd);

    let mut owned_privilege_keyword = PRIVILEGE_KEYWORD.to_owned();
    owned_privilege_keyword.push_str(&cmd);

    // println!("cmd after {:?}", owned_privilege_keyword);

    let hmac = generate_hmac(key_slice,  &owned_privilege_keyword);

    let (encrypted_cmd, nonce) = encrypt(key, cmd.as_bytes()).unwrap();
    let base64_encrypted_cmd = Base64::encode_string(&encrypted_cmd);
    let base64_encrypted_nonce = Base64::encode_string(&nonce);

    let mut privileged_cmd = Vec::new();
    privileged_cmd.push(PRIVILEGE_KEYWORD.to_owned());
    privileged_cmd.push(hmac);
    privileged_cmd.push(base64_encrypted_cmd);
    privileged_cmd.push(base64_encrypted_nonce);

    // println!("privileged cmd {:?}", privileged_cmd);

    privileged_cmd
}


pub fn verify_privileged_exec_cmd(privileged_cmd: &mut Vec<String>, key_slice: &[u8], key: &GenericArray<u8, U32>) -> Result<Vec<String>, super::error::Error>  {

    assert!(privileged_cmd.len() > 2);

    if privileged_cmd.len() != 4 {
        return  Err(super::error::Error::Common(format!("the privileged_cmd len is 4, len  {:?}, privileged_cmd verification failed", privileged_cmd.len())));
    }

    println!("verify_privileged_exec_cmd {:?}", privileged_cmd);

    let base64_encrypted_cmd = privileged_cmd.get(ENCRYPTED_MESSAGE_INDEX).unwrap();
    let base64_nonce = privileged_cmd.get(NONCE_INDEX).unwrap();

    let nonce_bytes = Base64::decode_vec(base64_nonce)
    .map_err(|e| super::error::Error::Common(format!("failed to decode the nonce, the error is {:?}, privileged_cmd verification failed", e)))?;

    let encrypted_cmd_bytes = Base64::decode_vec(base64_encrypted_cmd)
    .map_err(|e| super::error::Error::Common(format!("failed to decode the nonce, the error is {:?}, privileged_cmd verification failed", e)))?;

    let decrypted_cmd = decrypt(key, encrypted_cmd_bytes.as_slice(), nonce_bytes.as_slice())
    .map_err(|e| super::error::Error::Common(format!("failed to decrypted the cmd message, the error is {:?}, privileged_cmd verification failed", e)))?;



    let cmd_string = String::from_utf8(decrypted_cmd)
    .map_err(|e| super::error::Error::Common(format!("failed to turn the cmd from bytes to string, the error is {:?}, privileged_cmd verification failed", e)))?;

    let mut hmac_message = privileged_cmd.get(PRIVILEGE_KEYWORD_INDEX).unwrap().clone();
    hmac_message.push_str(&cmd_string);

    let base64_hmac = privileged_cmd.get(HMAC_INDEX).unwrap();

    let hmac_verify_res = verify_mac(key_slice, &hmac_message, base64_hmac);
    if hmac_verify_res == false {
        return Err(super::error::Error::Common(format!("hmac verification failed, privileged_cmd verification failed")));
    }

    let split = cmd_string.split_whitespace();
    let cmd_list = split.collect::<Vec<&str>>().iter().map(|&s| s.to_string()).collect::<Vec<String>>();

    println!("verification result  {:?}", cmd_list);
    return Ok(cmd_list);
}