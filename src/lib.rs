//! <h1> Pi Network Vanity </h1>
//!
//! This is a simple CLI tool for generating Pi Network vanity addresses.
//!
//! **Vanity Address:** similar to a vanity license plate, a vanity cryptocurrency address is an
//! address where either the beginning (prefix) or end (postfix) is a special or meaningful phrase.
//! Generating such an address requires work. Below is the expected time and difficulty of finding
//! different length words in a vanity address (based on a more optimized algorthim/codebase).
//!
//! ![https://imgur.com/diotZ02.png](https://imgur.com/diotZ02.png)
//!
//!
//!
//! # Examples
//! ```
//! pi_network_vanity AAA // Where AAA is the desired postfix
//! ```

extern crate base32;
extern crate byteorder;
extern crate bytes;
extern crate crc16;
extern crate ed25519_dalek;
extern crate rand;
extern crate rand_core;
extern crate stellar_base;
extern crate bip39;
extern crate slip10_ed25519;

pub mod vanity_key;
