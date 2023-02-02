use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, generic_array::{GenericArray, typenum::U32}},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
    Key,
};

use aes_gcm::aead::rand_core::RngCore;
// use anyhow::Ok;
use serde::*;



/// Nonce: unique per message.
/// 96-bits (12 bytes)
const NONCE_LENGTH: usize = 12;

pub struct KeyManager {
    pub counter: i64,
    pub key: GenericArray<u8, U32>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct IoFrame {
    pub nonce: Vec<u8>,
    // length: usize,
     // encrypted payload structure using aes-gcm
    pub pay_load: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default,Clone)]
struct PayLoad {
    pub counter: i64,
    pub data: Vec<u8>,
}

impl KeyManager {
    pub fn init() -> KeyManager {
        
        //for now, assume that the qkernel and client share this key
        const KEY_SLICE: &[u8; 32] = b"a very simple secret key to use!";

        KeyManager {
            counter:0,
            // key: Aes256Gcm::generate_key(&mut OsRng)
            key: Key::<Aes256Gcm>::from_slice(KEY_SLICE).clone()
        }
    }
}


fn encrypt(key: &GenericArray<u8, U32>, plain_txt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), super::error::Error> {
    let cipher = Aes256Gcm::new(key);

    let mut nonce_rnd = vec![0; NONCE_LENGTH];
    random_bytes(&mut nonce_rnd);
    let nonce = Nonce::from_slice(&nonce_rnd);

    let encrypt_msg = cipher.encrypt(nonce, plain_txt).map_err(|e| super::error::Error::Common(format!("failed to encryp the data error {:?}", e)))?;

    let mut cipher_txt = Vec::new();
    // cipher_txt.extend_from_slice(&nonce_rnd);
    cipher_txt.extend(encrypt_msg);
    Ok((cipher_txt, nonce_rnd.to_vec()))
}

fn decrypt(key: &GenericArray<u8, U32>, cipher_txt: &[u8], nouce: &[u8]) -> Result<Vec<u8>, super::error::Error> {
    // if cipher_txt.len() <= NONCE_LENGTH {
    //     bail!("cipher text is invalid");
    // }
    // let key = GenericArray::from_slice(self.key.as_slice());
    let cipher = Aes256Gcm::new(key);
    // let nonce_rnd = &cipher_txt[..NONCE_LENGTH];
    let nonce = Nonce::from_slice(nouce);
    let plain_txt = cipher
        .decrypt(nonce, &cipher_txt[..])
        .map_err(|e| super::error::Error::Common(format!("failed to dencryp the data error {:?}", e)))?;

    Ok(plain_txt)
}
    
fn prepare_encoded_io_frame(key: &GenericArray<u8, U32>, plain_text :&[u8]) -> Result<Vec<u8>, super::error::Error> {

    let mut payload = PayLoad::default();
    payload.counter = 1;
    payload.data = plain_text.to_vec();
    assert!(payload.data.len() == plain_text.len());

    let encoded_payload: Vec<u8> = postcard::to_allocvec(&payload).unwrap();

    let mut io_frame = IoFrame::default();

    (io_frame.pay_load, io_frame.nonce)= encrypt(key, encoded_payload.as_ref()).unwrap();

    let encoded_frame = postcard::to_allocvec(&io_frame).unwrap();

    Ok(encoded_frame)
}


fn encrypt_container_stdouterr (key: &GenericArray<u8, U32>, src: Vec<u8>) -> Vec<u8> {

    let encoded_out_bound_date = prepare_encoded_io_frame(key, src.as_slice()).unwrap();
    assert!(encoded_out_bound_date.len() != 0);

    // let mut res = DataBuff::New(encodedOutBoundDate.len());
    // res.buf = encodedOutBoundDate.clone();
    encoded_out_bound_date

}


fn random_bytes(slice: &mut [u8]) -> (){
    // let mut rmd_nonce= Vec::with_capacity(NONCE_LENGTH);
    // getrandom(&mut rmd_nonce).unwrap();
    assert!(slice.len() == NONCE_LENGTH);
    let mut rng = OsRng;
    rng.fill_bytes(slice);
    println!("generate nounce {:?}", slice);
    // rmd_nonce
    // thread_rng().gen::<[u8; NONCE_LENGTH]>()
}


/********************public function***********************************/


pub fn get_cmd_res_in_plaintext(key: &GenericArray<u8, U32>, encoded_payload : &mut Vec<u8>) -> Result<Vec<u8>, super::error::Error> {

    let body_slice: &mut [u8] = &mut encoded_payload[..];

    let frame =  postcard::from_bytes_cobs::<IoFrame>(body_slice)
            .map_err(|e| super::error::Error::Common(format!("failed to decode the slice in order to get the IOframe,  the  error is {:?}", e)))?;
    let decrypted = decrypt(key,&frame.pay_load, &frame.nonce).unwrap();
    let payload:PayLoad = postcard::from_bytes(decrypted.as_ref()).unwrap();

    Ok(payload.data)
}


pub fn get_decoded_payloads(key: &GenericArray<u8, U32>, frames :Vec<IoFrame>) -> Result<Vec<u8>, super::error::Error> {

    let mut data = Vec::new();
    for e in frames {

        let decrypted = decrypt(key, &e.pay_load, &e.nonce).unwrap();

        let mut payload:PayLoad =  postcard::from_bytes(decrypted.as_ref()).unwrap();

        data.append(&mut payload.data);

    }

    Ok(data)

}