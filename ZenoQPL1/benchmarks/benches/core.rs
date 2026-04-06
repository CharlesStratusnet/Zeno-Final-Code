use criterion::{criterion_group, criterion_main, Criterion};
use zeno_crypto::{default_scheme, SignatureScheme, SigningDomain};
use zeno_execution::ExecutionEngine;
use zeno_mempool::Mempool;
use zeno_primitives::sign_transaction;
use zeno_storage::MemoryStore;
use zeno_types::{Account, Address, ChainId, TransactionBody};

fn bench_crypto(c: &mut Criterion) {
    let scheme = default_scheme();
    let (pk, sk) = scheme.generate_keypair().expect("keypair");
    let message = b"benchmark-message";
    c.bench_function("ml_dsa_sign", |b| {
        b.iter(|| {
            scheme
                .sign(SigningDomain::Transaction, message, &sk)
                .expect("sign")
        })
    });
    let signature = scheme
        .sign(SigningDomain::Transaction, message, &sk)
        .expect("sign");
    c.bench_function("ml_dsa_verify", |b| {
        b.iter(|| {
            scheme
                .verify(SigningDomain::Transaction, message, &pk, &signature)
                .expect("verify")
        })
    });
}

fn bench_mempool(c: &mut Criterion) {
    let scheme = default_scheme();
    let (pk, sk) = scheme.generate_keypair().expect("keypair");
    let sender = Address(scheme.derive_address(&pk).expect("address"));
    c.bench_function("mempool_insert", |b| {
        b.iter(|| {
            let pool = Mempool::new();
            let tx = sign_transaction(
                &*scheme,
                TransactionBody {
                    chain_id: ChainId("bench".to_string()),
                    sender,
                    recipient: Address([7; 32]),
                    amount: 10,
                    nonce: 0,
                    fee: 1,
                    evm: None,
                    memo: None,
                    valid_until: Some(100),
                },
                pk.clone(),
                &sk,
            )
            .expect("sign");
            pool.insert(tx).expect("insert");
        })
    });
}

fn bench_execution(c: &mut Criterion) {
    let scheme = default_scheme();
    let store = MemoryStore::shared();
    let (pk, sk) = scheme.generate_keypair().expect("keypair");
    let sender = Address(scheme.derive_address(&pk).expect("address"));
    store
        .put_account(&sender, &Account { nonce: 0, balance: 1_000_000 })
        .expect("account");
    let tx = sign_transaction(
        &*scheme,
        TransactionBody {
            chain_id: ChainId("bench".to_string()),
            sender,
            recipient: Address([9; 32]),
            amount: 100,
            nonce: 0,
            fee: 1,
            evm: None,
            memo: None,
            valid_until: Some(100),
        },
        pk,
        &sk,
    )
    .expect("sign");
    let engine = ExecutionEngine::new(ChainId("bench".to_string()));
    c.bench_function("tx_verify_throughput", |b| {
        b.iter(|| {
            let state = zeno_state::StateSnapshot::load(&store).expect("state");
            engine
                .validate_transaction(&*scheme, &state, 1, &tx)
                .expect("validate")
        })
    });
}

criterion_group!(benches, bench_crypto, bench_mempool, bench_execution);
criterion_main!(benches);
