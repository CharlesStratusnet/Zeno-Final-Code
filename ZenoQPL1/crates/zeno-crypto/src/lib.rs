//! Post-quantum signing abstractions and ML-DSA implementation.

use std::sync::Arc;

use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use zeno_hash::{hash_bytes, Hash32};

/// Signing domains used for domain separation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningDomain {
    /// Account transaction signing.
    Transaction,
    /// Block proposal signing.
    BlockProposal,
    /// Consensus vote signing.
    ConsensusVote,
}

impl SigningDomain {
    /// Returns the canonical domain tag.
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::Transaction => b"zeno.tx.v1",
            Self::BlockProposal => b"zeno.block_proposal.v1",
            Self::ConsensusVote => b"zeno.consensus_vote.v1",
        }
    }
}

/// Supported ML-DSA levels. The underlying library currently exposes these
/// using Dilithium naming while tracking the same parameter families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MlDsaParameter {
    /// ML-DSA-44 / Dilithium2 equivalent security profile.
    MlDsa44,
    /// ML-DSA-65 / Dilithium3 equivalent security profile.
    #[default]
    MlDsa65,
    /// ML-DSA-87 / Dilithium5 equivalent security profile.
    MlDsa87,
}

impl MlDsaParameter {
    fn algorithm(self) -> Algorithm {
        match self {
            Self::MlDsa44 => Algorithm::MlDsa44,
            Self::MlDsa65 => Algorithm::MlDsa65,
            Self::MlDsa87 => Algorithm::MlDsa87,
        }
    }

    /// Human-readable description for docs and CLI output.
    pub const fn description(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44 compatible (Dilithium2 family)",
            Self::MlDsa65 => "ML-DSA-65 compatible (Dilithium3 family)",
            Self::MlDsa87 => "ML-DSA-87 compatible (Dilithium5 family)",
        }
    }
}

/// Public key wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct PublicKeyBytes(pub Vec<u8>);

/// Signature wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

/// Secret key wrapper.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes(pub Vec<u8>);

impl core::fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKeyBytes(REDACTED)")
    }
}

/// Address bytes derived from a public key.
pub type AddressBytes = [u8; 32];

/// Metadata describing key and signature sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSchemeMetadata {
    /// Public key length in bytes.
    pub public_key_bytes: usize,
    /// Secret key length in bytes.
    pub secret_key_bytes: usize,
    /// Signature length in bytes.
    pub signature_bytes: usize,
}

/// Cryptographic errors.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported or malformed key material")]
    MalformedKey,
    #[error("malformed signature")]
    MalformedSignature,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Verifiable signing scheme interface.
pub trait SignatureScheme: Send + Sync {
    /// Scheme metadata.
    fn metadata(&self) -> SignatureSchemeMetadata;

    /// Generates a new keypair.
    fn generate_keypair(&self) -> Result<(PublicKeyBytes, SecretKeyBytes), CryptoError>;

    /// Signs a canonical message in a given domain.
    fn sign(
        &self,
        domain: SigningDomain,
        message: &[u8],
        secret_key: &SecretKeyBytes,
    ) -> Result<SignatureBytes, CryptoError>;

    /// Verifies a canonical message in a given domain.
    fn verify(
        &self,
        domain: SigningDomain,
        message: &[u8],
        public_key: &PublicKeyBytes,
        signature: &SignatureBytes,
    ) -> Result<(), CryptoError>;

    /// Derives an account address from a public key.
    fn derive_address(&self, public_key: &PublicKeyBytes) -> Result<AddressBytes, CryptoError>;
}

/// Shared provider object.
pub type SharedSignatureScheme = Arc<dyn SignatureScheme>;

/// ML-DSA provider backed by liboqs.
pub struct MlDsaScheme {
    parameter: MlDsaParameter,
    sig: Sig,
}

impl MlDsaScheme {
    /// Creates a new ML-DSA scheme.
    pub fn new(parameter: MlDsaParameter) -> Result<Self, anyhow::Error> {
        oqs::init();
        let sig = Sig::new(parameter.algorithm()).map_err(|err| anyhow::anyhow!(err.to_string()))?;
        Ok(Self { parameter, sig })
    }

    fn domain_message(domain: SigningDomain, message: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(domain.tag().len() + 1 + message.len());
        bytes.extend_from_slice(domain.tag());
        bytes.push(0xff);
        bytes.extend_from_slice(message);
        bytes
    }
}

impl SignatureScheme for MlDsaScheme {
    fn metadata(&self) -> SignatureSchemeMetadata {
        SignatureSchemeMetadata {
            public_key_bytes: self.sig.length_public_key(),
            secret_key_bytes: self.sig.length_secret_key(),
            signature_bytes: self.sig.length_signature(),
        }
    }

    fn generate_keypair(&self) -> Result<(PublicKeyBytes, SecretKeyBytes), CryptoError> {
        let (public_key, secret_key) = self
            .sig
            .keypair()
            .map_err(|err| CryptoError::Backend(err.to_string()))?;
        Ok((
            PublicKeyBytes(public_key.into_vec()),
            SecretKeyBytes(secret_key.into_vec()),
        ))
    }

    fn sign(
        &self,
        domain: SigningDomain,
        message: &[u8],
        secret_key: &SecretKeyBytes,
    ) -> Result<SignatureBytes, CryptoError> {
        let msg = Self::domain_message(domain, message);
        let key = self
            .sig
            .secret_key_from_bytes(&secret_key.0)
            .ok_or(CryptoError::MalformedKey)?;
        let signature = self
            .sig
            .sign(&msg, key)
            .map_err(|err| CryptoError::Backend(err.to_string()))?;
        Ok(SignatureBytes(signature.into_vec()))
    }

    fn verify(
        &self,
        domain: SigningDomain,
        message: &[u8],
        public_key: &PublicKeyBytes,
        signature: &SignatureBytes,
    ) -> Result<(), CryptoError> {
        let msg = Self::domain_message(domain, message);
        let public_key = self
            .sig
            .public_key_from_bytes(&public_key.0)
            .ok_or(CryptoError::MalformedKey)?;
        let signature = self
            .sig
            .signature_from_bytes(&signature.0)
            .ok_or(CryptoError::MalformedSignature)?;
        self.sig
            .verify(&msg, signature, public_key)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn derive_address(&self, public_key: &PublicKeyBytes) -> Result<AddressBytes, CryptoError> {
        if public_key.0.len() != self.sig.length_public_key() {
            return Err(CryptoError::MalformedKey);
        }
        let mut bytes = b"zeno.address.v1".to_vec();
        bytes.extend_from_slice(&public_key.0);
        Ok(hash_bytes(bytes).0)
    }
}

/// Creates a shared ML-DSA provider.
pub fn default_scheme() -> SharedSignatureScheme {
    Arc::new(
        MlDsaScheme::new(MlDsaParameter::default())
            .expect("default ML-DSA provider must initialize"),
    )
}

/// Returns an address commitment for a public key.
pub fn public_key_fingerprint(public_key: &PublicKeyBytes) -> Hash32 {
    hash_bytes(&public_key.0)
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::{
        default_scheme, public_key_fingerprint, MlDsaParameter, MlDsaScheme, PublicKeyBytes,
        SecretKeyBytes, SignatureScheme, SigningDomain,
    };

    #[test]
    fn signs_and_verifies_transaction_messages() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let message = b"canonical tx bytes";
        let signature = scheme
            .sign(SigningDomain::Transaction, message, &sk)
            .expect("sign");
        scheme
            .verify(SigningDomain::Transaction, message, &pk, &signature)
            .expect("verify");
        assert!(scheme
            .verify(SigningDomain::ConsensusVote, message, &pk, &signature)
            .is_err());
    }

    #[test]
    fn rejects_malformed_key_material() {
        let scheme = MlDsaScheme::new(MlDsaParameter::MlDsa65).expect("scheme");
        let err = scheme
            .sign(
                SigningDomain::Transaction,
                b"hello",
                &SecretKeyBytes(vec![0u8; 8]),
            )
            .expect_err("must reject");
        assert!(matches!(err, super::CryptoError::MalformedKey));
    }

    #[test]
    fn address_derivation_is_stable() {
        let scheme = default_scheme();
        let (pk, _) = scheme.generate_keypair().expect("keypair");
        let address = scheme.derive_address(&pk).expect("address");
        let second = scheme.derive_address(&pk).expect("address");
        assert_eq!(address, second);
        assert_eq!(public_key_fingerprint(&pk), public_key_fingerprint(&pk));
    }

    #[test]
    fn known_vector_fingerprint_shape() {
        let public_key = PublicKeyBytes(Vec::from_hex("00112233445566778899aabbccddeeff").expect("hex"));
        let fingerprint = public_key_fingerprint(&public_key);
        assert_eq!(fingerprint.0.len(), 32);
    }

    #[test]
    fn different_domains_produce_different_signatures() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let message = b"same message";
        let sig_tx = scheme.sign(SigningDomain::Transaction, message, &sk).expect("sign tx");
        let sig_block = scheme.sign(SigningDomain::BlockProposal, message, &sk).expect("sign block");
        assert_ne!(sig_tx.0, sig_block.0);
    }

    #[test]
    fn wrong_key_verification_fails() {
        let scheme = default_scheme();
        let (_, sk_a) = scheme.generate_keypair().expect("keypair a");
        let (pk_b, _) = scheme.generate_keypair().expect("keypair b");
        let sig = scheme.sign(SigningDomain::Transaction, b"test", &sk_a).expect("sign");
        assert!(scheme.verify(SigningDomain::Transaction, b"test", &pk_b, &sig).is_err());
    }

    #[test]
    fn empty_message_signs_and_verifies() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sig = scheme.sign(SigningDomain::Transaction, b"", &sk).expect("sign");
        scheme.verify(SigningDomain::Transaction, b"", &pk, &sig).expect("verify");
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let scheme = default_scheme();
        let (_, sk) = scheme.generate_keypair().expect("keypair");
        let debug = format!("{sk:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&hex::encode(&sk.0[..8])));
    }

    #[test]
    fn metadata_has_positive_sizes() {
        let scheme = default_scheme();
        let meta = scheme.metadata();
        assert!(meta.public_key_bytes > 0);
        assert!(meta.secret_key_bytes > 0);
        assert!(meta.signature_bytes > 0);
    }
}
