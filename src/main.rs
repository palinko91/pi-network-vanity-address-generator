extern crate clap;
extern crate regex;
extern crate pi_network_vanity;
extern crate stellar_base;
extern crate bip39;
extern crate slip10_ed25519;
#[macro_use]
extern crate fstrings;

use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Instant;

use bip39::Mnemonic;
use bip39::Language;
use stellar_base::crypto::decode_secret_seed;
use slip10_ed25519::derive_ed25519_private_key;

use clap::{App, Arg};
use pi_network_vanity::vanity_key::{
    deserialize_private_key, deserialize_public_key, optimized_prefix_deserialize_public_key,
    AddressGenerator,
};

use regex::Regex;

fn main() {
    let matches = App::new("Pi Network Vanity Address Generator")
        .version("0.0.1")
        .author("Rob Durst , Arpad Palinkas.")
        .about("A simple CLI for generating Pi Network Vanity Addresses.")
        .arg(
            Arg::with_name("POSTFIX")
                .long("postfix")
                .takes_value(true)
                .help("desired address suffix"),
        )
        .arg(
            Arg::with_name("PREFIX")
                .long("prefix")
                .takes_value(true)
                .help("desired address prefix"),
        )
        .arg(
            Arg::with_name("THREADS_COUNT")
                .short("c")
                .takes_value(true)
                .default_value("1")
                .help("number of threads to use for searching"),
        )
        .get_matches();

    let threads_count: i64 = matches.value_of("THREADS_COUNT").unwrap().parse().unwrap();
    let postfix_option = Arc::new(matches.value_of("POSTFIX").map(|s| s.to_string()));
    let prefix_option = Arc::new(matches.value_of("PREFIX").map(|s| s.to_string()));

    let (tx, rx) = mpsc::channel();

    if threads_count == 1 {
        println!("\nSEARCHING INITIATED");
    } else {
        println!("\nSEARCHING INITIATED USING {} THREADS", threads_count);
    }

    let start = Instant::now();

    for _i in 0..threads_count {
        let thread_tx = tx.clone();
        let postfix_option = Arc::clone(&postfix_option);
        let prefix_option = Arc::clone(&prefix_option);

        let mut startre = Regex::new(r".").unwrap();
        let mut endre = Regex::new(r".").unwrap();

        if let Some(postfix) = &*postfix_option {
            let end = postfix.to_uppercase();
            endre = Regex::new(&f!("{end}$")).unwrap();
        }
        if let Some(prefix) = &*prefix_option {
            let start = prefix.to_uppercase();
            startre = Regex::new(&f!("^{start}")).unwrap();
        }

        thread::spawn(move || {
            let mut generator: AddressGenerator = Default::default();

            let keypair = generator
                .find(|key| {
                    let mut found = true;

                    if let None = &*postfix_option {
                        let pk = optimized_prefix_deserialize_public_key(key);
                        let key_str = pk.as_str();
                        found &= &startre.is_match(&key_str[2..]);
                    } else {
                        let pk = deserialize_public_key(key);
                        let key_str = pk.as_str();
                        found &= &startre.is_match(&key_str[2..]);
                        found &= &endre.is_match(&key_str);
                    }

                    found
                })
                .unwrap();

            thread_tx.send(keypair).unwrap();
        });
    }

    let keypair = rx.recv().unwrap();

    let duration = start.elapsed();

    let public_key = deserialize_public_key(&keypair);
    let private_key = deserialize_private_key(&keypair);

    println!(
        "\nSUCCESS!\nPublic Key: {:?}\nSecret Key: {:?}\n\nFound in {:?}\n\n",
        public_key, private_key, duration
    );

    //Storing the secret key for further processing
    let secret:String = private_key.to_string();

    //Secret key string to mnemonic words function for Stellar
    fn secret_to_stellar_mnemonic(secretkey:&String)->String {
        //Decode the secret key to bytes
        let kp = decode_secret_seed(&secretkey).unwrap();
        //Get the mnemonic positions from the entropy
        #[allow(non_snake_case)]
        let mnemo =  match Mnemonic::from_entropy_in(Language::English,&kp){
            Ok(Mnemonic)=> Mnemonic,
            Err(_)=> panic!("will be handled"),
        };
        //Make the actual words from the mnemonic positions
        let englishwords = Mnemonic::to_string(&mnemo);
        return englishwords;
    }
    let stellar_mnemo = secret_to_stellar_mnemonic(&secret);
    println!("Stellar mnemonic:  {:?}",stellar_mnemo);
    println!("\n");

    //Secret key string to mnemonic words function for Pi Network with derivated path
    fn secret_to_pi_mnemonic(secretkey:&String)->String{
        //Decode the secret key to bytes
        let kp = decode_secret_seed(&secretkey).unwrap();
        //Apply the derivation path for the byte secret key
        let derived = derive_ed25519_private_key(&kp, &vec!(44, 314159, 0));
        //Get the mnemonic positions from the entropy
        #[allow(non_snake_case)]
        let mnemo =  match Mnemonic::from_entropy_in(Language::English,&derived){
            Ok(Mnemonic)=> Mnemonic,
            Err(_)=> panic!("will be handled"),
        };
        //Make the actual words from the mnemonic positions
        let englishwords = Mnemonic::to_string(&mnemo);
        return englishwords;
    }
    let pi_mnemo = secret_to_pi_mnemonic(&secret);
    println!("Pi Network mnemonic:  {:?}",pi_mnemo);
    println!("\n");
}
