//! Core protocol helpers.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use zeno_crypto::{PublicKeyBytes, SignatureBytes, SignatureScheme, SigningDomain};
use zeno_hash::{hash_bytes, merkle_root, Hash32};
use zeno_types::{
    Address, Block, BlockHeader, ChainId, CommitCertificate, Proposal, Receipt, Transaction,
    TransactionBody, TransactionError, Vote,
};

/// Maximum memo size.
pub const MAX_MEMO_BYTES: usize = 256;
/// Maximum encoded transaction size (1 MB).
pub const MAX_TRANSACTION_SIZE: usize = 1_048_576;
/// Maximum EVM gas limit (30 million).
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Returns canonical transaction body bytes.
pub fn canonical_transaction_bytes(body: &TransactionBody) -> Result<Vec<u8>> {
    zeno_codec::encode(body).map_err(|err| anyhow!(err))
}

/// Returns canonical block header bytes.
pub fn canonical_block_header_bytes(header: &BlockHeader) -> Result<Vec<u8>> {
    zeno_codec::encode(header).map_err(|err| anyhow!(err))
}

/// Returns canonical vote bytes without the signature.
pub fn canonical_vote_bytes(
    height: u64,
    round: u32,
    step: zeno_types::VoteStep,
    block_hash: Hash32,
    validator_address: Address,
) -> Result<Vec<u8>> {
    #[derive(Serialize, Deserialize)]
    struct VoteSignable {
        height: u64,
        round: u32,
        step: zeno_types::VoteStep,
        block_hash: Hash32,
        validator_address: Address,
    }

    zeno_codec::encode(&VoteSignable {
        height,
        round,
        step,
        block_hash,
        validator_address,
    })
    .map_err(|err| anyhow!(err))
}

/// Derives the sender address from the provided public key.
pub fn sender_from_public_key(
    scheme: &dyn SignatureScheme,
    public_key: &[u8],
) -> Result<Address, TransactionError> {
    scheme
        .derive_address(&PublicKeyBytes(public_key.to_vec()))
        .map(Address)
        .map_err(|_| TransactionError::SenderMismatch)
}

/// Verifies a transaction signature and basic invariants.
pub fn verify_transaction(
    scheme: &dyn SignatureScheme,
    chain_id: &ChainId,
    tx: &Transaction,
    current_height: u64,
) -> Result<Vec<u8>, TransactionError> {
    // Size check — reject oversized transactions before doing expensive crypto.
    let encoded_size = zeno_codec::encode(tx)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    if encoded_size > MAX_TRANSACTION_SIZE {
        return Err(TransactionError::TransactionTooLarge(encoded_size));
    }
    if tx.body.amount == 0 && tx.body.evm.is_none() {
        return Err(TransactionError::ZeroAmount);
    }
    // EVM transactions must pay a meaningful fee to prevent compute spam.
    if let Some(ref evm) = tx.body.evm {
        if tx.body.fee < 10 {
            return Err(TransactionError::ZeroFee);
        }
    }
    if tx.body.fee == 0 {
        return Err(TransactionError::ZeroFee);
    }
    if tx.body.chain_id != *chain_id {
        return Err(TransactionError::WrongChainId);
    }
    if tx.body.memo.as_ref().is_some_and(|memo| memo.len() > MAX_MEMO_BYTES) {
        return Err(TransactionError::MemoTooLarge);
    }
    if let Some(valid_until) = tx.body.valid_until
        && current_height > valid_until
    {
        return Err(TransactionError::Expired(valid_until));
    }
    // Gas limit bounds for EVM transactions.
    if let Some(ref evm_tx) = tx.body.evm {
        if evm_tx.gas_limit == 0 || evm_tx.gas_limit > MAX_GAS_LIMIT {
            return Err(TransactionError::GasLimitExceeded {
                max: MAX_GAS_LIMIT,
                actual: evm_tx.gas_limit,
            });
        }
    }

    let derived = sender_from_public_key(scheme, &tx.public_key)?;
    if derived != tx.body.sender {
        return Err(TransactionError::SenderMismatch);
    }

    let body_bytes = canonical_transaction_bytes(&tx.body).map_err(|_| TransactionError::InvalidSignature)?;
    scheme
        .verify(
            SigningDomain::Transaction,
            &body_bytes,
            &PublicKeyBytes(tx.public_key.clone()),
            &SignatureBytes(tx.signature.clone()),
        )
        .map_err(|_| TransactionError::InvalidSignature)?;
    Ok(body_bytes)
}

/// Signs a transaction body and returns a complete transaction.
pub fn sign_transaction(
    scheme: &dyn SignatureScheme,
    body: TransactionBody,
    public_key: PublicKeyBytes,
    secret_key: &zeno_crypto::SecretKeyBytes,
) -> Result<Transaction> {
    let bytes = canonical_transaction_bytes(&body)?;
    let signature = scheme.sign(SigningDomain::Transaction, &bytes, secret_key)?;
    Ok(Transaction {
        body,
        public_key: public_key.0,
        signature: signature.0,
    })
}

/// Signs a block header.
pub fn sign_block(
    scheme: &dyn SignatureScheme,
    header: BlockHeader,
    transactions: Vec<Transaction>,
    proposer_public_key: PublicKeyBytes,
    secret_key: &zeno_crypto::SecretKeyBytes,
) -> Result<Block> {
    let bytes = canonical_block_header_bytes(&header)?;
    let signature = scheme.sign(SigningDomain::BlockProposal, &bytes, secret_key)?;
    Ok(Block {
        header,
        transactions,
        proposer_public_key: proposer_public_key.0,
        proposer_signature: signature.0,
    })
}

/// Verifies a block proposal.
pub fn verify_block(scheme: &dyn SignatureScheme, block: &Block) -> Result<()> {
    let derived = sender_from_public_key(scheme, &block.proposer_public_key)?;
    if derived != block.header.proposer {
        return Err(anyhow!("proposer address does not match public key"));
    }
    let bytes = canonical_block_header_bytes(&block.header)?;
    scheme.verify(
        SigningDomain::BlockProposal,
        &bytes,
        &PublicKeyBytes(block.proposer_public_key.clone()),
        &SignatureBytes(block.proposer_signature.clone()),
    )?;
    Ok(())
}

/// Signs a consensus vote.
pub fn sign_vote(
    scheme: &dyn SignatureScheme,
    mut vote: Vote,
    secret_key: &zeno_crypto::SecretKeyBytes,
) -> Result<Vote> {
    let bytes = canonical_vote_bytes(
        vote.height,
        vote.round,
        vote.step,
        vote.block_hash,
        vote.validator_address,
    )?;
    vote.signature = scheme
        .sign(SigningDomain::ConsensusVote, &bytes, secret_key)?
        .0;
    Ok(vote)
}

/// Verifies a consensus vote.
pub fn verify_vote(scheme: &dyn SignatureScheme, vote: &Vote) -> Result<()> {
    let bytes = canonical_vote_bytes(
        vote.height,
        vote.round,
        vote.step,
        vote.block_hash,
        vote.validator_address,
    )?;
    let address = sender_from_public_key(scheme, &vote.public_key)?;
    if address != vote.validator_address {
        return Err(anyhow!("vote signer mismatch"));
    }
    scheme.verify(
        SigningDomain::ConsensusVote,
        &bytes,
        &PublicKeyBytes(vote.public_key.clone()),
        &SignatureBytes(vote.signature.clone()),
    )?;
    Ok(())
}

/// Calculates the transaction merkle root.
pub fn transaction_root(transactions: &[Transaction]) -> Hash32 {
    let hashes: Vec<Hash32> = transactions.iter().map(Transaction::id).collect();
    merkle_root(&hashes)
}

/// Calculates the receipt merkle root.
pub fn receipt_root(receipts: &[Receipt]) -> Hash32 {
    let hashes: Vec<Hash32> = receipts
        .iter()
        .map(|receipt| hash_bytes(zeno_codec::encode(receipt).expect("receipt encode")))
        .collect();
    merkle_root(&hashes)
}

/// Calculates a proposal hash.
pub fn proposal_hash(proposal: &Proposal) -> Hash32 {
    hash_bytes(zeno_codec::encode(proposal).expect("proposal encode"))
}

/// Calculates a certificate hash for indexing.
pub fn certificate_hash(certificate: &CommitCertificate) -> Hash32 {
    hash_bytes(zeno_codec::encode(certificate).expect("certificate encode"))
}

#[cfg(test)]
mod tests {
    use zeno_crypto::default_scheme;
    use zeno_types::{ChainId, TransactionBody};

    use super::{canonical_transaction_bytes, sign_transaction, verify_transaction};

    #[test]
    fn canonical_tx_encoding_is_stable() {
        let body = TransactionBody {
            chain_id: ChainId("devnet".to_string()),
            sender: zeno_types::Address([1; 32]),
            recipient: zeno_types::Address([2; 32]),
            amount: 10,
            nonce: 1,
            fee: 2,
            evm: None,
            memo: Some("memo".to_string()),
            valid_until: Some(100),
        };
        let left = canonical_transaction_bytes(&body).expect("encode");
        let right = canonical_transaction_bytes(&body).expect("encode");
        assert_eq!(left, right);
    }

    #[test]
    fn transaction_signature_pipeline_roundtrips() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([9; 32]),
                amount: 25,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: Some(50),
            },
            pk,
            &sk,
        )
        .expect("sign");
        verify_transaction(&*scheme, &ChainId("devnet".to_string()), &tx, 10).expect("verify");
    }

    #[test]
    fn zero_amount_rejected() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([2; 32]),
                amount: 0,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: None,
            },
            pk,
            &sk,
        )
        .expect("sign");
        let err = verify_transaction(&*scheme, &ChainId("devnet".to_string()), &tx, 0).expect_err("must fail");
        assert!(matches!(err, zeno_types::TransactionError::ZeroAmount));
    }

    #[test]
    fn zero_fee_rejected() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([2; 32]),
                amount: 10,
                nonce: 0,
                fee: 0,
                evm: None,
                memo: None,
                valid_until: None,
            },
            pk,
            &sk,
        )
        .expect("sign");
        let err = verify_transaction(&*scheme, &ChainId("devnet".to_string()), &tx, 0).expect_err("must fail");
        assert!(matches!(err, zeno_types::TransactionError::ZeroFee));
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("wrong-chain".to_string()),
                sender,
                recipient: zeno_types::Address([2; 32]),
                amount: 10,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: None,
            },
            pk,
            &sk,
        )
        .expect("sign");
        let err = verify_transaction(&*scheme, &ChainId("devnet".to_string()), &tx, 0).expect_err("must fail");
        assert!(matches!(err, zeno_types::TransactionError::WrongChainId));
    }

    #[test]
    fn memo_too_large_rejected() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([2; 32]),
                amount: 10,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: Some("x".repeat(257)),
                valid_until: None,
            },
            pk,
            &sk,
        )
        .expect("sign");
        let err = verify_transaction(&*scheme, &ChainId("devnet".to_string()), &tx, 0).expect_err("must fail");
        assert!(matches!(err, zeno_types::TransactionError::MemoTooLarge));
    }

    #[test]
    fn expired_transaction_rejected() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let sender = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let tx = sign_transaction(
            &*scheme,
            TransactionBody {
                chain_id: ChainId("devnet".to_string()),
                sender,
                recipient: zeno_types::Address([2; 32]),
                amount: 10,
                nonce: 0,
                fee: 1,
                evm: None,
                memo: None,
                valid_until: Some(5),
            },
            pk,
            &sk,
        )
        .expect("sign");
        let err = verify_transaction(&*scheme, &ChainId("devnet".to_string()), &tx, 10).expect_err("must fail");
        assert!(matches!(err, zeno_types::TransactionError::Expired(5)));
    }

    #[test]
    fn transaction_root_empty() {
        let root = super::transaction_root(&[]);
        assert_ne!(root, zeno_hash::Hash32::zero());
    }

    #[test]
    fn receipt_root_empty() {
        let root = super::receipt_root(&[]);
        assert_ne!(root, zeno_hash::Hash32::zero());
    }

    #[test]
    fn block_signature_roundtrips() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let proposer = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let header = zeno_types::BlockHeader {
            height: 1,
            round: 0,
            chain_id: ChainId("devnet".to_string()),
            parent_hash: zeno_hash::Hash32::zero(),
            tx_root: zeno_hash::Hash32::zero(),
            state_root: zeno_hash::Hash32::zero(),
            receipt_root: zeno_hash::Hash32::zero(),
            proposer,
            timestamp_ms: 1,
        };
        let block = super::sign_block(&*scheme, header, Vec::new(), pk, &sk).expect("sign");
        super::verify_block(&*scheme, &block).expect("verify");
    }

    #[test]
    fn vote_signature_roundtrips() {
        let scheme = default_scheme();
        let (pk, sk) = scheme.generate_keypair().expect("keypair");
        let address = zeno_types::Address(scheme.derive_address(&pk).expect("address"));
        let vote = super::sign_vote(
            &*scheme,
            zeno_types::Vote {
                height: 1,
                round: 0,
                step: zeno_types::VoteStep::Prevote,
                block_hash: zeno_hash::Hash32::zero(),
                validator_address: address,
                public_key: pk.0,
                signature: Vec::new(),
            },
            &sk,
        )
        .expect("sign");
        super::verify_vote(&*scheme, &vote).expect("verify");
    }
}
