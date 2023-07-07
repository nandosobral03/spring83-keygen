extern crate rand_core;
use ed25519_dalek::*;
use rand_core::OsRng;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::available_parallelism;

const MAX_ITER: usize = 100_000_000;
const NUM_THREADS: usize = 16;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut default_parallelism = available_parallelism().unwrap().get();
    for i in 0..args.len() {
        if args[i] == "-t" {
            if i + 1 < args.len() {
                default_parallelism = args[i + 1].parse::<usize>().unwrap();
            }
        }
    }

    let timestart = chrono::Utc::now();
    let command = &args[1];
    match command.as_str() {
        "sign" => sign(),
        "generate" => generate(default_parallelism),
        _ => println!("Usage: {} [sign|generate]", args[0]),
    }
    let timeend = chrono::Utc::now();
    let duration = timeend - timestart;
    println!("Time taken: {:?}s", duration.num_seconds());
}

fn generate(default_parallelism: usize) {
    let result = Arc::new(Mutex::new(None));
    println!(
        "Executing on {} threads if you would prefer to use another number -t flag",
        &default_parallelism
    );
    let threads: Vec<_> = (0..default_parallelism)
        .map(|_| {
            let result = Arc::clone(&result);
            thread::spawn(move || {
                let mut iter = 0;
                loop {
                    let keypair: Keypair = Keypair::generate(&mut OsRng);
                    let public_key = keypair.public;
                    let secret_key = keypair.secret;
                    if validate_key(public_key.to_bytes().as_slice()) {
                        *result.lock().unwrap() = Some((public_key, secret_key));
                        break;
                    }

                    iter += 1;
                    if iter % 100000 == 0 {
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
        let filename = "./keypair.txt";
        let contents = format!(
            "Secret key:\n{}\nPublic key:\n{}\n",
            hex::encode(secret_key.to_bytes()),
            hex::encode(public_key.to_bytes())
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
    let keypair_bytes = hex::decode(keypair_string).unwrap();
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

pub fn validate_key(key: &[u8]) -> bool {
    let year_bit = key[31];

    let month_bit = key[30];
    // Month takes 2 nibs, if the first nib is 0, then the month is 0-9, its its 1 then the other nib is 0-2
    let first_nib = month_bit & 0xF0;
    let second_nib = month_bit & 0x0F;

    let nib3e = key[29];
    let nib8 = key[28] & 0x0F;

    return (year_bit == 0x22 || year_bit == 0x23)
        && nib3e == 0x3e
        && nib8 == 0x8
        && ((first_nib == 0x10 && second_nib < 0x3) || (first_nib == 0x00 && second_nib < 0xA));
}
