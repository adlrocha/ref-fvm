// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use std::convert::TryInto;
use std::hash::Hash;
use std::u64;

use super::{
    from_leb_bytes, to_leb_bytes, Error, Protocol, BLS_PUB_LEN, HA_LEVEL_LEN, HA_ROOT_LEN,
    MAX_ADDRESS_LEN, PAYLOAD_HASH_LEN, RAW_ADDR_LEN,
};

/// Payload is the data of the Address. Variants are the supported Address protocols.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum Payload {
    /// ID protocol address.
    ID(u64),
    /// SECP256K1 key address, 20 byte hash of PublicKey
    Secp256k1([u8; PAYLOAD_HASH_LEN]),
    /// Actor protocol address, 20 byte hash of actor data
    Actor([u8; PAYLOAD_HASH_LEN]),
    /// BLS key address, full 48 byte public key
    BLS([u8; BLS_PUB_LEN]),
    /// Hierarchical address. Up to 64 bytes long
    Hierarchical([u8; MAX_ADDRESS_LEN]),
}

fn truncate_hc_payload(raw: [u8; MAX_ADDRESS_LEN]) -> Vec<u8> {
    let mut bz = raw.to_vec();
    // extract levels and set size of address according to number
    // of levels (to allow the padding to show to many redundant
    // characters)
    let levels = from_leb_bytes(&[bz[0]]).unwrap();
    // 2 - levels + end separator
    bz.drain(..HA_ROOT_LEN + (levels as usize - 1) * HA_LEVEL_LEN + RAW_ADDR_LEN + 2)
        .collect()
}

impl Payload {
    /// Returns encoded bytes of Address without the protocol byte.
    pub fn to_raw_bytes(self) -> Vec<u8> {
        use Payload::*;
        match self {
            ID(i) => to_leb_bytes(i).unwrap(),
            Secp256k1(arr) => arr.to_vec(),
            Actor(arr) => arr.to_vec(),
            BLS(arr) => arr.to_vec(),
            Hierarchical(arr) => truncate_hc_payload(arr),
        }
    }

    /// Returns encoded bytes of Address including the protocol byte.
    pub fn to_bytes(self) -> Vec<u8> {
        use Payload::*;
        let mut bz = match self {
            ID(i) => to_leb_bytes(i).unwrap(),
            Secp256k1(arr) => arr.to_vec(),
            Actor(arr) => arr.to_vec(),
            BLS(arr) => arr.to_vec(),
            Hierarchical(arr) => truncate_hc_payload(arr),
        };

        bz.insert(0, Protocol::from(self) as u8);
        bz
    }

    /// Generates payload from raw bytes and protocol.
    pub fn new(protocol: Protocol, payload: &[u8]) -> Result<Self, Error> {
        let payload = match protocol {
            Protocol::ID => Self::ID(from_leb_bytes(payload)?),
            Protocol::Secp256k1 => Self::Secp256k1(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
            Protocol::Actor => Self::Actor(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
            Protocol::BLS => Self::BLS(
                payload
                    .try_into()
                    .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
            ),
            Protocol::Hierarchical => {
                // paste truncated payload into right size array
                let mut extended = [0u8; MAX_ADDRESS_LEN];
                extended[..payload.len()].copy_from_slice(payload);
                Self::Hierarchical(
                    extended
                        .try_into()
                        .map_err(|_| Error::InvalidPayloadLength(payload.len()))?,
                )
            }
        };
        Ok(payload)
    }
}

impl From<Payload> for Protocol {
    fn from(pl: Payload) -> Self {
        match pl {
            Payload::ID(_) => Self::ID,
            Payload::Secp256k1(_) => Self::Secp256k1,
            Payload::Actor(_) => Self::Actor,
            Payload::BLS(_) => Self::BLS,
            Payload::Hierarchical(_) => Self::Hierarchical,
        }
    }
}

impl From<&Payload> for Protocol {
    fn from(pl: &Payload) -> Self {
        match pl {
            Payload::ID(_) => Self::ID,
            Payload::Secp256k1(_) => Self::Secp256k1,
            Payload::Actor(_) => Self::Actor,
            Payload::BLS(_) => Self::BLS,
            Payload::Hierarchical(_) => Self::Hierarchical,
        }
    }
}

#[cfg(feature = "testing")]
impl Default for Payload {
    fn default() -> Self {
        Payload::ID(0)
    }
}
