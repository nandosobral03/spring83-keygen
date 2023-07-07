extern crate rand_core;
use chrono::Datelike;
use ed25519_dalek::*;

use rand_core::OsRng;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;

const MAX_ITER: usize = 10000000;
const NUM_THREADS: usize = 1;

fn main() {

// check args
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} [sign|generate]", args[0]);
        return;
    }

    let command = &args[1]; 
    match command.as_str() {
        "sign" => sign(),
        "generate" => generate(),
        _ => println!("Usage: {} [sign|generate]", args[0]),
    }

   
}


fn generate() {
    let result = Arc::new(Mutex::new(None));

    let threads: Vec<_> = (0..NUM_THREADS)
        .map(|_| {
            let result = Arc::clone(&result);
            thread::spawn(move || {
                let mut iter = 0;
                loop {
                    let keypair: Keypair = Keypair::generate(&mut OsRng);
                    println!("{:?}", hex::encode(keypair.to_bytes()));
                    let public_key = keypair.public;
                    let secret_key = keypair.secret;
                    if validate_key(hex::encode(public_key.to_bytes()).as_str()) {
                        *result.lock().unwrap() = Some((public_key, secret_key));
                        break;
                    }

                    iter += 1;
                    if iter % 10000 == 0 {
                        println!("{} iterations in thread {:?}", iter, thread::current().id());
                    }
                    if iter == MAX_ITER / NUM_THREADS {
                        println!("No valid key found for thread {:?}", thread::current().id());
                        break;
                    }

                    if result.lock().unwrap().is_some() {
                        break;
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let result = result.lock().unwrap();
    if let Some((public_key, secret_key)) = result.as_ref() {
        println!("Valid key found");
        let filename = "./keypair.txt";
        println!("{:?}", public_key.to_bytes().len());
        println!("{:?}", secret_key.to_bytes().len());
        let contents = format!(
            "Secret key:\n{}\nPublic key:\n{}\n",
            hex::encode(secret_key.to_bytes()), hex::encode(public_key.to_bytes())

        );
        fs::write(filename, contents).expect("Unable to write file");
    }
}

fn sign() {
    let html = "Secret".to_string();
    let filename = "./keypair.txt";
    let contents = fs::read_to_string(filename).expect("Something went wrong reading the file");
    let lines: Vec<&str> = contents.split("\n").collect();
    let keypair_string = format!("{}{}", lines[1], lines[3]);
    let keypair_bytes =hex::decode(keypair_string).unwrap();
    let keypair: Keypair = Keypair::from_bytes(&keypair_bytes).unwrap();
    println!("{:?}", &html.as_bytes());
    let signature = keypair.sign(html.as_bytes());
    let signature = hex::encode(signature.to_bytes());
    println!("SECRET {:?}", &keypair.secret.to_bytes());
    println!("PUBLIC {:?}", &keypair.public.to_bytes());    
    println!("Done signing");


    let public_key = lines[3];
    println!("{}", public_key);
    let public_key = PublicKey::from_bytes(hex::decode(public_key).unwrap().as_slice()).unwrap();
    println!("Get public key");
    let signature_from_hex = hex::decode(signature).unwrap();
    let signature = Signature::from_bytes(signature_from_hex.as_slice()).unwrap();
    public_key.verify(html.as_bytes(), &signature).unwrap();
    println!("{}", signature);
    println!("{}", html);
}

pub fn validate_key(key: &str) -> bool {
    // [a-zA-Z0-9]+83e(0[1-9]|1[0-2])(\d\d)$
    return true;
    let re = regex::Regex::new(r"^[a-zA-Z0-9]+83e(0[1-9]|1[0-2])(\d\d)$").unwrap();
    if !re.is_match(key){
        return false;
    }

    let month = &key[64 - 4..64 - 2];
    let year = &key[64 - 2..64];

    if year != "23" && year != "22" {
        return false;
    }

    // if year == current_year - 2 && month < current_month {
    //     return false;
    // }

    // if year == current_year && month > current_month {
    //     return false;
    // }
    return true;
}
