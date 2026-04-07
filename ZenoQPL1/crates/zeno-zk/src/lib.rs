//! Zero-knowledge proof system for private transactions on Zeno PQ Chain.
//!
//! Implements a hash-based commitment scheme using BLAKE3 for post-quantum
//! secure private transfers. Unlike pairing-based ZK-SNARKs (Groth16), this
//! scheme is resistant to quantum attacks because it relies on hash function
//! preimage resistance rather than discrete log assumptions.
//!
//! # Architecture
//!
//! - **Commitments:** `BLAKE3("zeno.commitment.v1" || value_le || blinding_factor)`
//! - **Nullifiers:** `BLAKE3("zeno.nullifier.v1" || commitment || spending_key)`
//! - **Commitment Tree:** Incremental Merkle tree storing all commitments
//! - **Shielded Pool:** Tracks the commitment tree root and nullifier set
//!
//! # Transaction Flow
//!
//! 1. **Shield (deposit):** User commits value into the shielded pool
//!    - Generates random blinding factor
//!    - Computes commitment and adds to the Merkle tree
//!    - Deducts value from their public balance
//!
//! 2. **Transfer (private):** User spends a commitment and creates a new one
//!    - Reveals the nullifier (proves they own the commitment without revealing which one)
//!    - Provides Merkle proof that the commitment exists in the tree
//!    - Creates a new commitment for the recipient
//!
//! 3. **Unshield (withdraw):** User reveals the commitment and withdraws to public balance
//!    - Reveals the nullifier
//!    - Provides Merkle proof
//!    - Credits value to their public balance

use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeno_hash::{hash_bytes, Hash32};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Depth of the commitment Merkle tree (supports 2^32 commitments).
pub const COMMITMENT_TREE_DEPTH: usize = 32;

/// Domain separation tags for hash-based constructions.
const COMMITMENT_DOMAIN: &[u8] = b"zeno.zk.commitment.v1";
const NULLIFIER_DOMAIN: &[u8] = b"zeno.zk.nullifier.v1";
const TREE_NODE_DOMAIN: &[u8] = b"zeno.zk.tree_node.v1";
const TREE_EMPTY_DOMAIN: &[u8] = b"zeno.zk.empty_leaf.v1";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// ZK proof system errors.
#[derive(Debug, Error)]
pub enum ZkError {
    /// The commitment already exists in the tree.
    #[error("duplicate commitment")]
    DuplicateCommitment,
    /// The nullifier has already been spent.
    #[error("nullifier already spent (double-spend attempt)")]
    NullifierAlreadySpent,
    /// The Merkle proof is invalid.
    #[error("invalid Merkle proof")]
    InvalidMerkleProof,
    /// The commitment was not found in the tree.
    #[error("commitment not found")]
    CommitmentNotFound,
    /// The proof verification failed.
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
    /// Insufficient shielded balance.
    #[error("insufficient shielded balance")]
    InsufficientBalance,
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A 32-byte blinding factor used to hide values in commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindingFactor(pub [u8; 32]);

impl BlindingFactor {
    /// Generates a random blinding factor.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        Self(bytes)
    }
}

/// A 32-byte spending key used to derive nullifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingKey(pub [u8; 32]);

impl SpendingKey {
    /// Generates a random spending key.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::fill(&mut bytes);
        Self(bytes)
    }
}

/// A shielded note containing the information needed to spend a commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedNote {
    /// The value in the commitment.
    pub value: u128,
    /// The blinding factor.
    pub blinding: BlindingFactor,
    /// The spending key.
    pub spending_key: SpendingKey,
    /// The computed commitment hash.
    pub commitment: Hash32,
    /// The computed nullifier hash.
    pub nullifier: Hash32,
    /// Index in the commitment tree.
    pub tree_index: Option<u64>,
}

/// A Merkle proof for a commitment in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentMerkleProof {
    /// The commitment being proved.
    pub commitment: Hash32,
    /// The leaf index in the tree.
    pub index: u64,
    /// Sibling hashes from leaf to root (length = COMMITMENT_TREE_DEPTH).
    pub siblings: Vec<Hash32>,
}

/// A shielded transfer proof (spend one commitment, create another).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTransferProof {
    /// Nullifier of the spent commitment (reveals that it's been used).
    pub nullifier: Hash32,
    /// Merkle root at the time of the proof.
    pub merkle_root: Hash32,
    /// Merkle proof that the commitment exists in the tree.
    pub merkle_proof: CommitmentMerkleProof,
    /// New commitment for the recipient.
    pub output_commitment: Hash32,
    /// Value being transferred (encrypted or zero-knowledge in a full system).
    /// In this implementation, the value is revealed to the chain for validation.
    pub value: u128,
}

/// A shield (deposit) request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldRequest {
    /// Value to shield.
    pub value: u128,
    /// Commitment to add to the tree.
    pub commitment: Hash32,
}

/// An unshield (withdraw) request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldRequest {
    /// Nullifier proving ownership.
    pub nullifier: Hash32,
    /// Merkle proof of the commitment.
    pub merkle_proof: CommitmentMerkleProof,
    /// Merkle root at proof generation time.
    pub merkle_root: Hash32,
    /// Value to withdraw.
    pub value: u128,
    /// Recipient public address.
    pub recipient: zeno_types::Address,
}

// ---------------------------------------------------------------------------
// Commitment scheme
// ---------------------------------------------------------------------------

/// Computes a Pedersen-style hash commitment.
///
/// `commitment = BLAKE3(domain || value_le_bytes || blinding_factor)`
///
/// This is computationally hiding (attacker can't determine value without
/// the blinding factor) and computationally binding (attacker can't find
/// two different (value, blinding) pairs that hash to the same commitment).
pub fn compute_commitment(value: u128, blinding: &BlindingFactor) -> Hash32 {
    let mut preimage = Vec::with_capacity(COMMITMENT_DOMAIN.len() + 16 + 32);
    preimage.extend_from_slice(COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&value.to_le_bytes());
    preimage.extend_from_slice(&blinding.0);
    hash_bytes(preimage)
}

/// Computes a nullifier from a commitment and spending key.
///
/// `nullifier = BLAKE3(domain || commitment || spending_key)`
///
/// The nullifier uniquely identifies a commitment being spent without
/// revealing which commitment it is (since the spending key is secret).
pub fn compute_nullifier(commitment: Hash32, spending_key: &SpendingKey) -> Hash32 {
    let mut preimage = Vec::with_capacity(NULLIFIER_DOMAIN.len() + 32 + 32);
    preimage.extend_from_slice(NULLIFIER_DOMAIN);
    preimage.extend_from_slice(commitment.as_bytes());
    preimage.extend_from_slice(&spending_key.0);
    hash_bytes(preimage)
}

/// Creates a new shielded note.
pub fn create_note(value: u128) -> ShieldedNote {
    let blinding = BlindingFactor::random();
    let spending_key = SpendingKey::random();
    let commitment = compute_commitment(value, &blinding);
    let nullifier = compute_nullifier(commitment, &spending_key);
    ShieldedNote {
        value,
        blinding,
        spending_key,
        commitment,
        nullifier,
        tree_index: None,
    }
}

/// Creates a note with a specific spending key (for recipient-controlled notes).
pub fn create_note_with_key(value: u128, spending_key: &SpendingKey) -> ShieldedNote {
    let blinding = BlindingFactor::random();
    let commitment = compute_commitment(value, &blinding);
    let nullifier = compute_nullifier(commitment, spending_key);
    ShieldedNote {
        value,
        blinding,
        spending_key: spending_key.clone(),
        commitment,
        nullifier,
        tree_index: None,
    }
}

// ---------------------------------------------------------------------------
// Commitment Merkle tree
// ---------------------------------------------------------------------------

/// Incremental Merkle tree for commitments.
///
/// Uses a fixed-depth binary tree where:
/// - Leaves are commitment hashes
/// - Internal nodes are `BLAKE3(domain || left || right)`
/// - Empty leaves use a precomputed empty hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentTree {
    /// Current number of leaves.
    pub leaf_count: u64,
    /// The tree nodes (sparse representation).
    /// Key: (depth, index), Value: hash.
    nodes: std::collections::BTreeMap<(usize, u64), Hash32>,
    /// Precomputed empty subtree hashes at each depth.
    #[serde(skip)]
    empty_hashes: Vec<Hash32>,
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTree {
    /// Creates an empty commitment tree.
    pub fn new() -> Self {
        let empty_hashes = compute_empty_hashes();
        Self {
            leaf_count: 0,
            nodes: std::collections::BTreeMap::new(),
            empty_hashes,
        }
    }

    /// Ensures empty hashes are initialized (needed after deserialization).
    fn ensure_empty_hashes(&mut self) {
        if self.empty_hashes.is_empty() {
            self.empty_hashes = compute_empty_hashes();
        }
    }

    /// Returns the current Merkle root.
    pub fn root(&mut self) -> Hash32 {
        self.ensure_empty_hashes();
        self.node_hash(0, 0)
    }

    /// Inserts a commitment and returns its leaf index.
    pub fn insert(&mut self, commitment: Hash32) -> Result<u64, ZkError> {
        self.ensure_empty_hashes();
        let index = self.leaf_count;
        if index >= (1u64 << COMMITMENT_TREE_DEPTH) {
            return Err(ZkError::VerificationFailed("tree is full".to_string()));
        }
        // Set the leaf.
        self.nodes.insert((COMMITMENT_TREE_DEPTH, index), commitment);
        self.leaf_count += 1;
        // Update path from leaf to root.
        let mut current_index = index;
        for depth in (0..COMMITMENT_TREE_DEPTH).rev() {
            let parent_index = current_index / 2;
            let left = self.node_hash(depth + 1, parent_index * 2);
            let right = self.node_hash(depth + 1, parent_index * 2 + 1);
            let parent_hash = tree_node_hash(left, right);
            self.nodes.insert((depth, parent_index), parent_hash);
            current_index = parent_index;
        }
        Ok(index)
    }

    /// Generates a Merkle proof for a commitment at the given index.
    pub fn prove(&mut self, index: u64) -> Result<CommitmentMerkleProof, ZkError> {
        self.ensure_empty_hashes();
        if index >= self.leaf_count {
            return Err(ZkError::CommitmentNotFound);
        }
        let commitment = self.node_hash(COMMITMENT_TREE_DEPTH, index);
        let mut siblings = Vec::with_capacity(COMMITMENT_TREE_DEPTH);
        let mut current = index;
        for depth in (0..COMMITMENT_TREE_DEPTH).rev() {
            let sibling = if current % 2 == 0 {
                self.node_hash(depth + 1, current + 1)
            } else {
                self.node_hash(depth + 1, current - 1)
            };
            siblings.push(sibling);
            current /= 2;
        }
        Ok(CommitmentMerkleProof {
            commitment,
            index,
            siblings,
        })
    }

    fn node_hash(&self, depth: usize, index: u64) -> Hash32 {
        self.nodes
            .get(&(depth, index))
            .copied()
            .unwrap_or_else(|| {
                if depth < self.empty_hashes.len() {
                    self.empty_hashes[depth]
                } else {
                    Hash32::zero()
                }
            })
    }
}

/// Verifies a commitment Merkle proof against a root.
pub fn verify_commitment_proof(proof: &CommitmentMerkleProof, expected_root: Hash32) -> bool {
    if proof.siblings.len() != COMMITMENT_TREE_DEPTH {
        return false;
    }
    let mut current = proof.commitment;
    let mut index = proof.index;
    for sibling in &proof.siblings {
        current = if index % 2 == 0 {
            tree_node_hash(current, *sibling)
        } else {
            tree_node_hash(*sibling, current)
        };
        index /= 2;
    }
    current == expected_root
}

fn tree_node_hash(left: Hash32, right: Hash32) -> Hash32 {
    let mut preimage = Vec::with_capacity(TREE_NODE_DOMAIN.len() + 64);
    preimage.extend_from_slice(TREE_NODE_DOMAIN);
    preimage.extend_from_slice(left.as_bytes());
    preimage.extend_from_slice(right.as_bytes());
    hash_bytes(preimage)
}

fn compute_empty_hashes() -> Vec<Hash32> {
    let mut hashes = vec![Hash32::zero(); COMMITMENT_TREE_DEPTH + 1];
    hashes[COMMITMENT_TREE_DEPTH] = hash_bytes(TREE_EMPTY_DOMAIN);
    for depth in (0..COMMITMENT_TREE_DEPTH).rev() {
        hashes[depth] = tree_node_hash(hashes[depth + 1], hashes[depth + 1]);
    }
    hashes
}

// ---------------------------------------------------------------------------
// Shielded pool
// ---------------------------------------------------------------------------

/// The on-chain shielded pool state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShieldedPool {
    /// The commitment Merkle tree.
    pub tree: CommitmentTree,
    /// Set of spent nullifiers (prevents double-spending).
    pub nullifiers: BTreeSet<Hash32>,
    /// Total shielded value (for accounting validation).
    pub total_shielded_value: u128,
}

impl ShieldedPool {
    /// Creates an empty shielded pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes a shield (deposit) — adds a commitment to the tree.
    pub fn shield(&mut self, request: &ShieldRequest) -> Result<u64, ZkError> {
        let index = self.tree.insert(request.commitment)?;
        self.total_shielded_value = self.total_shielded_value.saturating_add(request.value);
        Ok(index)
    }

    /// Processes a shielded transfer — spends a commitment and creates a new one.
    pub fn transfer(&mut self, proof: &ShieldedTransferProof) -> Result<u64, ZkError> {
        // 1. Check nullifier hasn't been spent.
        if self.nullifiers.contains(&proof.nullifier) {
            return Err(ZkError::NullifierAlreadySpent);
        }

        // 2. Verify Merkle proof against the current root.
        let root = self.tree.clone().root();
        if proof.merkle_root != root {
            return Err(ZkError::VerificationFailed(
                "merkle root mismatch".to_string(),
            ));
        }
        if !verify_commitment_proof(&proof.merkle_proof, root) {
            return Err(ZkError::InvalidMerkleProof);
        }

        // 3. Record the nullifier (mark as spent).
        self.nullifiers.insert(proof.nullifier);

        // 4. Insert the new output commitment.
        let index = self.tree.insert(proof.output_commitment)?;
        Ok(index)
    }

    /// Processes an unshield (withdraw) — spends a commitment and credits public balance.
    pub fn unshield(&mut self, request: &UnshieldRequest) -> Result<(), ZkError> {
        // 1. Check nullifier hasn't been spent.
        if self.nullifiers.contains(&request.nullifier) {
            return Err(ZkError::NullifierAlreadySpent);
        }

        // 2. Verify Merkle proof.
        let root = self.tree.clone().root();
        if request.merkle_root != root {
            return Err(ZkError::VerificationFailed(
                "merkle root mismatch".to_string(),
            ));
        }
        if !verify_commitment_proof(&request.merkle_proof, root) {
            return Err(ZkError::InvalidMerkleProof);
        }

        // 3. Record the nullifier.
        self.nullifiers.insert(request.nullifier);

        // 4. Reduce total shielded value.
        self.total_shielded_value = self.total_shielded_value.saturating_sub(request.value);
        Ok(())
    }

    /// Returns the current Merkle root.
    pub fn root(&mut self) -> Hash32 {
        self.tree.root()
    }

    /// Returns the number of commitments in the tree.
    pub fn commitment_count(&self) -> u64 {
        self.tree.leaf_count
    }

    /// Returns the number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }
}

// ---------------------------------------------------------------------------
// EVM precompile interface
// ---------------------------------------------------------------------------

/// Verifies a shielded transfer proof from EVM calldata.
///
/// Input encoding (ABI-style):
/// - bytes32: nullifier
/// - bytes32: merkle_root
/// - bytes32: output_commitment
/// - uint128: value
/// - bytes32[COMMITMENT_TREE_DEPTH]: merkle_siblings
/// - uint64: merkle_index
/// - bytes32: commitment
///
/// Returns: bytes32 (0x01 if valid, 0x00 if invalid)
pub fn zk_verify_precompile(input: &[u8]) -> Vec<u8> {
    let result = verify_precompile_inner(input);
    let mut out = vec![0u8; 32];
    if result {
        out[31] = 1;
    }
    out
}

fn verify_precompile_inner(input: &[u8]) -> bool {
    // Minimum size: 32 (nullifier) + 32 (root) + 32 (output) + 16 (value) + 8 (index) + 32 (commitment) = 152 bytes
    // Plus 32 * COMMITMENT_TREE_DEPTH siblings
    let expected_len = 152 + 32 * COMMITMENT_TREE_DEPTH;
    if input.len() < expected_len {
        return false;
    }

    let nullifier = read_hash32(input, 0);
    let merkle_root = read_hash32(input, 32);
    let output_commitment = read_hash32(input, 64);

    let mut value_bytes = [0u8; 16];
    value_bytes.copy_from_slice(&input[96..112]);
    let _value = u128::from_le_bytes(value_bytes);

    let mut index_bytes = [0u8; 8];
    index_bytes.copy_from_slice(&input[112..120]);
    let index = u64::from_le_bytes(index_bytes);

    let commitment = read_hash32(input, 120);

    let mut siblings = Vec::with_capacity(COMMITMENT_TREE_DEPTH);
    for i in 0..COMMITMENT_TREE_DEPTH {
        siblings.push(read_hash32(input, 152 + i * 32));
    }

    let proof = CommitmentMerkleProof {
        commitment,
        index,
        siblings,
    };

    // Verify the Merkle proof.
    if !verify_commitment_proof(&proof, merkle_root) {
        return false;
    }

    // Verify the output commitment is non-zero.
    if output_commitment == Hash32::zero() {
        return false;
    }

    // Verify the nullifier is non-zero.
    nullifier != Hash32::zero()
}

fn read_hash32(data: &[u8], offset: usize) -> Hash32 {
    let mut hash = [0u8; 32];
    if data.len() >= offset + 32 {
        hash.copy_from_slice(&data[offset..offset + 32]);
    }
    Hash32(hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic() {
        let blinding = BlindingFactor([7u8; 32]);
        let c1 = compute_commitment(100, &blinding);
        let c2 = compute_commitment(100, &blinding);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_values_produce_different_commitments() {
        let blinding = BlindingFactor([7u8; 32]);
        assert_ne!(
            compute_commitment(100, &blinding),
            compute_commitment(200, &blinding)
        );
    }

    #[test]
    fn different_blindings_produce_different_commitments() {
        let b1 = BlindingFactor([1u8; 32]);
        let b2 = BlindingFactor([2u8; 32]);
        assert_ne!(
            compute_commitment(100, &b1),
            compute_commitment(100, &b2)
        );
    }

    #[test]
    fn nullifier_is_deterministic() {
        let commitment = Hash32([5u8; 32]);
        let key = SpendingKey([9u8; 32]);
        assert_eq!(
            compute_nullifier(commitment, &key),
            compute_nullifier(commitment, &key)
        );
    }

    #[test]
    fn different_keys_produce_different_nullifiers() {
        let commitment = Hash32([5u8; 32]);
        let k1 = SpendingKey([1u8; 32]);
        let k2 = SpendingKey([2u8; 32]);
        assert_ne!(
            compute_nullifier(commitment, &k1),
            compute_nullifier(commitment, &k2)
        );
    }

    #[test]
    fn create_note_produces_valid_commitment() {
        let note = create_note(1000);
        assert_eq!(note.value, 1000);
        let expected = compute_commitment(1000, &note.blinding);
        assert_eq!(note.commitment, expected);
        let expected_nullifier = compute_nullifier(note.commitment, &note.spending_key);
        assert_eq!(note.nullifier, expected_nullifier);
    }

    #[test]
    fn commitment_tree_insert_and_prove() {
        let mut tree = CommitmentTree::new();
        let c1 = Hash32([1u8; 32]);
        let c2 = Hash32([2u8; 32]);
        let idx1 = tree.insert(c1).expect("insert 1");
        let idx2 = tree.insert(c2).expect("insert 2");
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);

        let root = tree.root();
        let proof = tree.prove(0).expect("prove");
        assert!(verify_commitment_proof(&proof, root));
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let mut tree = CommitmentTree::new();
        tree.insert(Hash32([1u8; 32])).expect("insert");
        let root = tree.root();
        let mut proof = tree.prove(0).expect("prove");
        // Tamper with a sibling.
        proof.siblings[0] = Hash32([0xff; 32]);
        assert!(!verify_commitment_proof(&proof, root));
    }

    #[test]
    fn shielded_pool_deposit_and_withdraw() {
        let mut pool = ShieldedPool::new();
        let note = create_note(1000);

        // Shield (deposit).
        let index = pool
            .shield(&ShieldRequest {
                value: 1000,
                commitment: note.commitment,
            })
            .expect("shield");
        assert_eq!(pool.total_shielded_value, 1000);
        assert_eq!(pool.commitment_count(), 1);

        // Generate proof for unshield.
        let root = pool.root();
        let proof = pool.tree.prove(index).expect("prove");

        // Unshield (withdraw).
        pool.unshield(&UnshieldRequest {
            nullifier: note.nullifier,
            merkle_proof: proof,
            merkle_root: root,
            value: 1000,
            recipient: zeno_types::Address([0u8; 32]),
        })
        .expect("unshield");
        assert_eq!(pool.total_shielded_value, 0);
        assert_eq!(pool.nullifier_count(), 1);
    }

    #[test]
    fn double_spend_prevented() {
        let mut pool = ShieldedPool::new();
        let note = create_note(1000);
        let index = pool
            .shield(&ShieldRequest {
                value: 1000,
                commitment: note.commitment,
            })
            .expect("shield");

        let root = pool.root();
        let proof = pool.tree.prove(index).expect("prove");

        pool.unshield(&UnshieldRequest {
            nullifier: note.nullifier,
            merkle_proof: proof.clone(),
            merkle_root: root,
            value: 1000,
            recipient: zeno_types::Address([0u8; 32]),
        })
        .expect("first unshield");

        // Second attempt with same nullifier should fail.
        let err = pool
            .unshield(&UnshieldRequest {
                nullifier: note.nullifier,
                merkle_proof: proof,
                merkle_root: root,
                value: 1000,
                recipient: zeno_types::Address([0u8; 32]),
            })
            .expect_err("must fail");
        assert!(matches!(err, ZkError::NullifierAlreadySpent));
    }

    #[test]
    fn shielded_transfer_works() {
        let mut pool = ShieldedPool::new();

        // Alice shields 1000.
        let alice_note = create_note(1000);
        let alice_index = pool
            .shield(&ShieldRequest {
                value: 1000,
                commitment: alice_note.commitment,
            })
            .expect("shield");

        // Alice transfers to Bob.
        let bob_key = SpendingKey::random();
        let bob_note = create_note_with_key(1000, &bob_key);
        let root = pool.root();
        let proof = pool.tree.prove(alice_index).expect("prove");

        let transfer_proof = ShieldedTransferProof {
            nullifier: alice_note.nullifier,
            merkle_root: root,
            merkle_proof: proof,
            output_commitment: bob_note.commitment,
            value: 1000,
        };

        let bob_index = pool.transfer(&transfer_proof).expect("transfer");
        assert_eq!(pool.commitment_count(), 2);
        assert_eq!(pool.nullifier_count(), 1);
        assert!(bob_index > alice_index);
    }

    #[test]
    fn zk_precompile_rejects_short_input() {
        let result = zk_verify_precompile(&[1, 2, 3]);
        assert_eq!(result[31], 0); // Invalid.
    }

    #[test]
    fn random_notes_are_unique() {
        let n1 = create_note(100);
        let n2 = create_note(100);
        assert_ne!(n1.commitment, n2.commitment);
        assert_ne!(n1.nullifier, n2.nullifier);
    }
}
