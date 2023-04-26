

use sha2::{Sha256};
use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use super::encryption_utilities::*;
use aes_gcm::{
    aead::{generic_array::{GenericArray, typenum::U32}}
};
use rand::Rng;

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
