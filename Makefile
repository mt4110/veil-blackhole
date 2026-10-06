.PHONY: build test lint run

build:
	cargo build --locked

test:
	cargo test --locked
	python3 -B -m unittest discover -s tests -p 'test_*.py'

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings

run:
	cargo run --locked -- replay --fixture tests/fixtures/query-a.hex
