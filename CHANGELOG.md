All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release of the Twilight WASM SDK.
- WebAssembly (WASM) bindings for core Twilight blockchain client operations.
- Support for account management, transaction creation, and cryptographic utilities in browser environments.
- Integration with the new `twilight-client-sdk` as a dependency.
- Comprehensive Rust and WASM documentation.
- Example usage and build instructions in `README.md`.
- Apache 2.0 license for open source compliance.
- Minimal CI workflow for formatting, linting, testing, and WASM build.
- `.gitignore` and project structure for professional open source development.

### Changed
- Migrated from private/internal codebase to a clean, public-facing repository.
- Updated all references from legacy `zkos-client-wallet` to `twilight-client-sdk`.
- Improved code comments and removed legacy or commented-out code for clarity.

### Removed
- All private keys, secrets, and sensitive data.
- Legacy and deprecated code paths not relevant to WASM/browser use.

---