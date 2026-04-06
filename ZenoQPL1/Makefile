.PHONY: fmt check test bench devnet-up devnet-down devnet-genesis

fmt:
	cargo fmt --all

check:
	cargo check --workspace

test:
	cargo test --workspace

bench:
	cargo bench --workspace

devnet-genesis:
	cargo run --bin zeno-cli -- node init-devnet --output ./devnet

devnet-up:
	docker compose -f docker/docker-compose.devnet.yml up --build

devnet-down:
	docker compose -f docker/docker-compose.devnet.yml down -v
