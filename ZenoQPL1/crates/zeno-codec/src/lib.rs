//! Deterministic binary encoding helpers used across the protocol.

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Canonical bincode configuration.
pub fn config() -> impl bincode::config::Config {
    bincode::config::standard()
        .with_fixed_int_encoding()
        .with_little_endian()
}

/// Errors raised during canonical encoding.
#[derive(Debug, Error)]
pub enum CodecError {
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("trailing bytes detected")]
    TrailingBytes,
}

/// Encodes a serializable value using the canonical configuration.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    bincode::serde::encode_to_vec(value, config()).map_err(|err| CodecError::Encode(err.to_string()))
}

/// Decodes a value and rejects trailing bytes.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    let (value, consumed): (T, usize) = bincode::serde::decode_from_slice(bytes, config())
        .map_err(|err| CodecError::Decode(err.to_string()))?;
    if consumed != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{decode, encode};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Example {
        nonce: u64,
        memo: String,
    }

    #[test]
    fn canonical_roundtrip_is_stable() {
        let value = Example {
            nonce: 7,
            memo: "hello".to_string(),
        };
        let left = encode(&value).expect("encode");
        let right = encode(&value).expect("encode");
        assert_eq!(left, right);
        assert_eq!(decode::<Example>(&left).expect("decode"), value);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = encode(&42u64).expect("encode");
        bytes.push(0);
        let err = decode::<u64>(&bytes).expect_err("must fail");
        assert!(matches!(err, super::CodecError::TrailingBytes));
    }

    #[test]
    fn u128_roundtrip() {
        let value: u128 = 999_999_999_999_999;
        let bytes = encode(&value).expect("encode");
        assert_eq!(decode::<u128>(&bytes).expect("decode"), value);
    }

    #[test]
    fn string_roundtrip() {
        let value = "hello world".to_string();
        let bytes = encode(&value).expect("encode");
        assert_eq!(decode::<String>(&bytes).expect("decode"), value);
    }

    #[test]
    fn nested_struct_roundtrip() {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct Outer {
            inner: Example,
            flag: bool,
        }
        let value = Outer {
            inner: Example {
                nonce: 42,
                memo: "nested".to_string(),
            },
            flag: true,
        };
        let bytes = encode(&value).expect("encode");
        assert_eq!(decode::<Outer>(&bytes).expect("decode"), value);
    }

    #[test]
    fn empty_bytes_decode_fails() {
        assert!(decode::<u64>(&[]).is_err());
    }

    #[test]
    fn bool_roundtrip() {
        let bytes = encode(&true).expect("encode");
        assert!(decode::<bool>(&bytes).expect("decode"));
    }
}
