# Mostro Core

Mostro Core is a Rust-based library that provides peer-to-peer functionality for decentralized applications. It serves as the foundation for building Mostro daemon.

## Requirements

- Rust 1.86.0 or later
- Cargo (Rust's package manager)
- [cargo-release](https://crates.io/crates/cargo-release) for releasing new versions
- [git-cliff](https://crates.io/crates/git-cliff) for generating the changelog

### Installing git-cliff

git-cliff is used to automatically generate changelogs from git commits. You can install it using one of the following methods:

#### Using Cargo (Recommended)
```bash
cargo install git-cliff
```

#### Using Package Managers
- **Ubuntu/Debian**: `sudo apt install git-cliff`
- **macOS (Homebrew)**: `brew install git-cliff`
- **Arch Linux**: `sudo pacman -S git-cliff`
- **Fedora**: `sudo dnf install git-cliff`

#### Using Pre-built Binaries
Download the latest release from the [git-cliff releases page](https://github.com/orhun/git-cliff/releases) and extract the binary to your PATH.

#### Verify Installation
```bash
git cliff --version
```

## Features

- Peer-to-peer networking capabilities
- Secure communication protocols
- Efficient data synchronization
- Cross-platform compatibility

## Import prelude to use mostro core

```rust
use mostro_core::prelude::*;
```

## Contribute

You may be interested in contributing to Mostro. If you're looking for somewhere to start contributing, check out the [good first issue](https://github.com/MostroP2P/mostro-core/labels/good%20first%20issue) list.

More info in our [contributing guide](contributing.md) and the focused [Repository Guidelines](AGENTS.md) for agent contributors.

## Documentation

- Protocol documentation: [https://mostro.network/protocol](https://mostro.network/protocol/)
- Frequently Asked Questions: in [English](https://mostro.network/docs-english/), in [Spanish](https://mostro.network/docs-spanish/).

## License

Mostro is licensed under the [MIT license](LICENSE).
