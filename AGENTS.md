# Repository Guidelines

## Project Structure & Module Organization
Mostro Core is a Rust library with `src/lib.rs` orchestrating modules that mirror domain entities. Core data models and logic live in files such as `src/order.rs`, `src/message.rs`, `src/user.rs`, while cryptographic helpers sit in `src/crypto.rs` and dispute flows in `src/dispute.rs`. Shared exports intended for consumers are re-exported through `src/prelude.rs`. Inline unit tests reside beside their modules under `#[cfg(test)]`. Enable optional capabilities through Cargo features: `wasm` ships by default and `sqlx` adds persistence helpers.

## Build, Test, and Development Commands
- `cargo check` — fast type checking before committing.
- `cargo build --release` — produce optimized artifacts before cutting a release.
- `cargo test` — run unit tests; append `--features sqlx` when exercising database traits.
- `cargo fmt` and `cargo clippy -- -D warnings` — enforce formatting and lint gates.
- `cargo doc --open` — review generated API docs when adding or renaming exports.

## Coding Style & Naming Conventions
Code targets Rust 1.86.0 (2021 edition). Favor clear module boundaries and avoid leaking internals outside the prelude unless necessary. Use `snake_case` for functions and modules, `PascalCase` for types and enums, and `SCREAMING_SNAKE_CASE` for constants. Document public APIs with `///` comments and keep error enums exhaustive. Always run `cargo fmt` before pushing and address clippy warnings immediately.

## Testing Guidelines
Place new unit tests in the same module inside `#[cfg(test)] mod tests` blocks with descriptive names like `test_signature_roundtrip`. Cover failure paths around invalid currencies, dispute resolution, and crypto edge cases. Reuse existing builders or helpers instead of duplicating fixtures. Run `cargo test --all-features` before opening a PR to ensure feature parity.

## Commit & Pull Request Guidelines
Follow Conventional Commits (e.g., `feat:`, `fix:`, `chore:`) and sign commits when possible. Keep commits focused and squash noisy iterations prior to review. Pull requests should summarise scope, list affected modules or features, and explain validation steps (tests, docs, screenshots for API changes). Link related issues and request review in Telegram if the change is time-sensitive.
