extern crate rand_core;
use chrono::Datelike;
use ed25519_dalek::*;
use rand_core::OsRng;
use std::fs;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::available_parallelism;

const MAX_ITER: usize = 100_000_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut default_parallelism = available_parallelism().unwrap().get();

    let year = chrono::Utc::now().year().to_string();
    let mut year = &year[2..4];

    for i in 0..args.len() {
        if args[i] == "-t" {
            if i + 1 < args.len() {
                default_parallelism = args[i + 1].parse::<usize>().unwrap();
            }
        }
        if args[i] == "-y" {
            if i + 1 < args.len() {
                year = &args[i + 1];
            }
        }
    }
    println!(
        "Searching for a key ending with {} or {}",
        year.parse::<u8>().unwrap() - 1,
        year,
    );
    let time_start = chrono::Utc::now();
    generate(default_parallelism, hex::decode(year).unwrap()[0]);
    let time_end = chrono::Utc::now();
    let duration = time_end - time_start;
    println!("Time taken: {:?}s", duration.num_seconds());
}

fn generate(default_parallelism: usize, year: u8) {
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
                    if validate_key(public_key.to_bytes().as_slice(), year) {
                        *result.lock().unwrap() = Some((public_key, secret_key));
                        break;
                    }

                    iter += 1;
                    if iter % 100000 == 0 {
                        println!("{} iterations in thread {:?}", iter, thread::current().id());
                    }
                    if iter == MAX_ITER / default_parallelism {
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
        println!("Found keypair");
        println!("Secret key: {}", hex::encode(secret_key.to_bytes()));
        println!("Public key: {}", hex::encode(public_key.to_bytes()));
        println!("Saved to {}", filename);
    } else {
        println!("No valid key found");
    }
    println!("Press Ctrl+C to exit...");
    loop {}
}

pub fn validate_key(key: &[u8], year: u8) -> bool {
    let year_bit = key[31];

    let month_bit = key[30];
    let first_nib = month_bit & 0xF0;
    let second_nib = month_bit & 0x0F;

    let nib3e = key[29];
    let nib8 = key[28] & 0x0F;

    return (year_bit == year || year_bit == year - 1)
        && nib3e == 0x3e
        && nib8 == 0x8
        && ((first_nib == 0x10 && second_nib < 0x3)
            || (first_nib == 0x00 && second_nib < 0xA && second_nib > 0x0));
}
