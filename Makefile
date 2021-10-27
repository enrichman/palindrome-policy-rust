.PHONY: build
build:
	cargo build --target=wasm32-unknown-unknown --release

.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: test
test: fmt lint
	cargo test

.PHONY: e2e-tests
e2e-tests:
	bats e2e.bats

.PHONY: clean
clean:
	cargo clean
