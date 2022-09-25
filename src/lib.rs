#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use std::rc::Rc;

use chacha20poly1305::{
  aead::{ AeadCore, KeyInit, OsRng, Aead },
  ChaCha20Poly1305, Nonce, Key
};

#[napi]
pub struct Cipher{
  key: Key,
  cipher: chacha20poly1305::ChaCha20Poly1305,
  nonce: Nonce,
}
#[derive(Clone)]
enum CipherType {
  Key(Key),
  ChaCha20Poly1305(ChaCha20Poly1305),
  Nonce(Nonce),
}

impl Into<Key> for CipherType {
  fn into(self) -> Key {
    match self {
      CipherType::Key(key) => key,
      _ => panic!("Cannot convert to Key"),
    }
  }
}

impl Into<ChaCha20Poly1305> for CipherType {
  fn into(self) -> ChaCha20Poly1305 {
    match self {
      CipherType::ChaCha20Poly1305(cipher) => cipher,
      _ => panic!("Cannot convert to ChaCha20Poly1305"),
    }
  }
}

impl Into<Nonce> for CipherType {
  fn into(self) -> Nonce {
    match self {
      CipherType::Nonce(nonce) => nonce,
      _ => panic!("Cannot convert to Nonce"),
    }
  }
}


#[napi]
impl Cipher {
  
  #[napi(constructor)]
  pub fn new(key_: Option<Vec<u8>>,nonce_: Option<Vec<u8>>) -> Cipher {
    let mut data:Vec<CipherType>  = Vec::new();
    if let Some(key) = key_ {
      let converted_key = Rc::new(Key::from_slice(&key));
      let cipher = ChaCha20Poly1305::new(&Rc::clone(&converted_key));
      data.push(CipherType::Key(**converted_key));
      data.push(CipherType::ChaCha20Poly1305(cipher));
    } else {
      let key = Rc::new(ChaCha20Poly1305::generate_key(&mut OsRng));
      let cipher = ChaCha20Poly1305::new(&Rc::clone(&key));
      data.push(CipherType::Key(*key));
      data.push(CipherType::ChaCha20Poly1305(cipher));
    };
    
    if let Some(nonce) = nonce_ {
      let converted_nonce = Nonce::from_slice(&nonce);
      data.push(CipherType::Nonce(*converted_nonce));
    } else {
      let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
      data.push(CipherType::Nonce(nonce));
    };
    
    Cipher {
      key: data[0].clone().into(),
      cipher: data[1].clone().into(),
      nonce: data[2].clone().into(),
    }
  }

  #[napi]
  pub fn encrypt(&self, data: String) -> Vec<u8> {
    let ciphertext = self.cipher.encrypt(&self.nonce, data.as_bytes()).unwrap();
    ciphertext.to_vec()
  }
  // .into_iter().map(|x| x.to_string()).collect::<Vec<String>>().join("")

  #[napi]
  pub fn decrypt(&self, data: Vec<u8>) -> String {
    let plaintext = self.cipher.decrypt(&self.nonce, data.as_ref()).unwrap();
    String::from_utf8(plaintext).unwrap()
  }

  #[napi]
  pub fn get_key(&self) -> Vec<u8> {
    self.key.to_vec()
  }

  #[napi]
  pub fn get_nonce(&self) -> Vec<u8> {
    self.nonce.to_vec()
  }

}