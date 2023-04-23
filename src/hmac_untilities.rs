

use sha2::{Sha256};
use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use super::encryption_utilities::*;
use aes_gcm::{
    aead::{generic_array::{GenericArray, typenum::U32}}
};
use rand::Rng;


const PRIVILEGE_KEYWORD_INDEX: usize = 0;
const HMAC_INDEX: usize = 1;
const ENCRYPTED_MESSAGE_INDEX: usize = 2;
const NONCE_INDEX: usize = 3;
const PRIVILEGE_KEYWORD: &str = "Privileged ";


#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Session {
    session_id: u32,
    pub counter: u32,
}

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
 *         Privileged / hmac(Privileged|Session_id|Conter|cmd|args, privilegd_user_key) /  (Session_id + Conter + cmd + args) / nonce
 * ************************ ************************************************
 */
pub fn prepare_priviled_exec_cmd(cmd: String, key_slice: &[u8], key: &GenericArray<u8, U32>, s: &mut Session) -> Vec<String> {

    // println!("cmd before {:?}", cmd);

    let mut owned_privilege_keyword = PRIVILEGE_KEYWORD.to_owned();
    owned_privilege_keyword.push_str(&s.session_id.to_string());
    owned_privilege_keyword.push_str(&" ".to_string());
    owned_privilege_keyword.push_str(&s.counter.to_string());
    owned_privilege_keyword.push_str(&" ".to_string());
    owned_privilege_keyword.push_str(&cmd);

    // println!("cmd after {:?}", owned_privilege_keyword);

    let hmac = generate_hmac(key_slice,  &owned_privilege_keyword);

    let mut privileged_cmd_payload = s.session_id.to_string();
    privileged_cmd_payload.push_str(&" ".to_string());
    privileged_cmd_payload.push_str(&s.counter.to_string());
    privileged_cmd_payload.push_str(&" ".to_string());
    privileged_cmd_payload.push_str(&cmd.to_string());

    let (encrypted_cmd, nonce) = encrypt(key, privileged_cmd_payload.as_bytes()).unwrap();
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

    println!("verify_privileged_exec_cmd cmd{:?}", cmd_string);

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



/**
 * Login phase
 * Step 1: Secure client sends "Privilege login request":
 * *********************** * *********************** ************************
 *         Privileged /  hmac(Login|random_number, privilegd_user_key) /    (Keyword "Login" + random_number) encrypted by privilegd_user_key / nonce
 * ************************ ************************************************
 * Note:
 * We use random numbers to avoid known-plaintext attacks in the case that the key space is too small 
 * https://crypto.stackexchange.com/questions/8500/with-hmac-can-an-attacker-recover-the-key-given-many-known-plaintext-tag-pairs
 * 
 * Step 2: qkernel returns session metadata via stdout of qkernel exec process:
 * *********************** * *********************** ************************
 *         (Session_id + Conter +  Session expire time) encrypted by privilegd_user_key / nonce
 * ************************ ************************************************ 
 * 
 * Request resource phase:
 * 
 * Step 1: Secure client sends exec request with session metadata attached:
 * *********************** * *********************** ************************
 *         Privileged / hmac(Session_id|Conter|Session_expire_time|cmd|args, privilegd_user_key) /  (Session_id + Session_expire_time + Conter + cmd + args) / nonce
 * ************************ ************************************************
 * 
 * Step 2: qkernel return the exec result to secure client over stdout of qkernel exec process:
 * *********************** * *********************** ************************
 *        (exec result + session is expered) encrypted by privilegd_user_key / nonce
 * ************************ ************************************************                          
 */
pub fn prepare_secure_vm_login_req(key_slice: &[u8], key: &GenericArray<u8, U32>) -> Vec<String> {
    // println!("cmd before {:?}", cmd);

    const LOGIN_KEYWORD: &str = "Login ";

    let mut privileged_login_req_payload = LOGIN_KEYWORD.to_owned();

    let rnd : i64= rand::thread_rng().gen();
    let rnd_string = rnd.to_string();
    privileged_login_req_payload.push_str(&rnd_string);



    let mut hmac_input = PRIVILEGE_KEYWORD.to_owned();
    hmac_input.push_str(&privileged_login_req_payload);
    println!("privileged_login_req_payload hmac message {:?}", hmac_input);


    let hmac = generate_hmac(key_slice,  &hmac_input);


    let (encrypted_privileged_login_req_payload, nonce) = encrypt(key, privileged_login_req_payload.as_bytes()).unwrap();
    let base64_encrypted_privileged_login_req_payload = Base64::encode_string(&encrypted_privileged_login_req_payload);
    let base64_encrypted_nonce = Base64::encode_string(&nonce);

    let mut privileged_login_req = Vec::new();
    privileged_login_req.push(PRIVILEGE_KEYWORD.to_owned());
    privileged_login_req.push(hmac);
    privileged_login_req.push(base64_encrypted_privileged_login_req_payload);
    privileged_login_req.push(base64_encrypted_nonce);

    // println!("privileged cmd {:?}", privileged_cmd);

    privileged_login_req
}




// /**
//  * Privilege request format:                  
//  * *********************** * *********************** ************************
//  *         Privileged / hmac(Privileged|Session_id|Conter|cmd|args, privilegd_user_key) /  (Session_id + Conter + cmd + args) / nonce
//  * ************************ ************************************************
//  */
// pub fn prepare_secret_update_req(policy: String, key_slice: &[u8], key: &GenericArray<u8, U32>, s: &mut Session) -> Vec<String> {

//     // println!("cmd before {:?}", cmd);
//     const POLICY_UPDATE_KEYWORD: &str = "PolicyUpdate ";

//     let mut owned_privilege_keyword = PRIVILEGE_KEYWORD.to_owned();
//     owned_privilege_keyword.push_str(&s.session_id.to_string());
//     owned_privilege_keyword.push_str(&" ".to_string());
//     owned_privilege_keyword.push_str(&s.counter.to_string());
//     owned_privilege_keyword.push_str(&" ".to_string());
//     owned_privilege_keyword.push_str(POLICY_UPDATE_KEYWORD);
//     owned_privilege_keyword.push_str(&policy);


//     // println!("cmd after {:?}", owned_privilege_keyword);

//     let hmac = generate_hmac(key_slice,  &owned_privilege_keyword);

//     let mut privileged_cmd_payload = s.session_id.to_string();
//     privileged_cmd_payload.push_str(&" ".to_string());
//     privileged_cmd_payload.push_str(&s.counter.to_string());
//     privileged_cmd_payload.push_str(&" ".to_string());
//     privileged_cmd_payload.push_str(&cmd.to_string());

//     let (encrypted_cmd, nonce) = encrypt(key, privileged_cmd_payload.as_bytes()).unwrap();
//     let base64_encrypted_cmd = Base64::encode_string(&encrypted_cmd);
//     let base64_encrypted_nonce = Base64::encode_string(&nonce);

//     let mut privileged_cmd = Vec::new();
//     privileged_cmd.push(PRIVILEGE_KEYWORD.to_owned());
//     privileged_cmd.push(hmac);
//     privileged_cmd.push(base64_encrypted_cmd);
//     privileged_cmd.push(base64_encrypted_nonce);

//     // println!("privileged cmd {:?}", privileged_cmd);

//     privileged_cmd
// }
