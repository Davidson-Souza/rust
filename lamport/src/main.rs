extern crate sha256;
extern crate rand;

use rand::Rng;

#[allow(unused)]
#[allow(dead_code)]
#[derive(Debug)]

struct LamportPrivkey {
    n_length: u8,
    priv_key: Vec<u128>,
}

impl LamportPrivkey {
    fn new() -> LamportPrivkey {
        LamportPrivkey {
            n_length:16,
            priv_key: Vec::new(),
        }
    }
    fn get(mut self) -> LamportPrivkey {
        for i in 0..16 {
            let secret_number:u128 = rand::thread_rng().gen_range(1..101);
            self.priv_key.push(secret_number);
        }
        self
    }
}

#[derive(Debug)]
pub struct LamportPubKey {
    n_length: u8,
    pub_key: Vec<String>,
}
impl LamportPubKey {
    fn new() -> LamportPubKey {
        LamportPubKey {
            n_length:8,
            pub_key: Vec::new(),
        }
    }
    fn derive(priv_key: &LamportPrivkey) -> LamportPubKey {
        let mut pub_key = LamportPubKey {
            n_length:8,
            pub_key: Vec::new(),
        };
        for i in 0..priv_key.n_length as usize {
            let key = sha256::digest_bytes(&priv_key.priv_key[i].to_le_bytes());
            pub_key.pub_key.push(key);
        }
        pub_key
    }
}

#[derive(Debug)]
pub struct LamportSig {
    n_length: u8,
    pub_key: LamportPubKey,
    sig: Vec<u128>
}
impl LamportSig {
    fn sign(priv_key: LamportPrivkey, data: &u8) -> LamportSig {
        let pub_key = LamportPubKey::derive(&priv_key);
        let mut lamport_sig = LamportSig {
            n_length: 8,
            pub_key: pub_key,
            sig: Vec::new(),
        };
        for i in 0..(lamport_sig.n_length) {
            lamport_sig.sig.push(priv_key.priv_key[(if (data & 1) == 1 {2*i} else {(2*i) + 1} as usize)]);
        };
        lamport_sig
    }
    fn verify(sig: &LamportSig, data: &u8) -> bool {
        let mut verified: bool = true;
        let mut index = 0;
        for i in sig.sig.iter() {
            let hash = sha256::digest_bytes(&i.to_le_bytes());
            if hash != sig.pub_key.pub_key[if(data & 1) == 1 { index } else {index + 1} as usize] {
                verified = false;
                break;
            }
            index+= 2;
        };

        verified
    }
}

fn main() {
    let key = LamportPrivkey::new();    // Create a lamport key
    let key = key.get();
    
    println!("{:?}", LamportPubKey::derive(&key));
    let data = 1;

    let sig = LamportSig::sign(key, &data);     // Create sig
    println!("{:?}", sig);
    println!("{}", LamportSig::verify(&sig, &data));
}