# Twilight Client WASM

WebAssembly bindings for Twilight protocol operations, enabling zero-knowledge trading and lending directly in browsers.

## Features

- 🔐 **Account Management**: Secure key generation and address creation
- 💱 **Trading Operations**: Zero-knowledge trading with privacy preservation  
- 🏦 **Lending Operations**: Decentralized lending protocol integration
- 🔒 **Cryptographic Utilities**: Advanced cryptographic operations
- 🌐 **Browser Compatible**: Run Twilight operations directly in web applications

## Quick Start

```bash
# Install wasm-pack
cargo install wasm-pack

# Build the WASM package
wasm-pack build --target web

# Use in your web application
import init, { generatePublicKeyFromSignature } from './pkg/twilight_wasm.js';
```

## API Documentation

[Link to detailed API docs]

## Examples

[Link to example implementations]

## License

Licensed under Apache 2.0. See [LICENSE](LICENSE) for details. 
