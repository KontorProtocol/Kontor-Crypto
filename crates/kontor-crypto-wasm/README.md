# kontor-crypto-wasm

WASM bindings for Kontor PoR **prepare_file**: callable from the browser or Node.js. Uses `kontor-crypto-core` (no `nova_poseidon`) so the build stays WASM-compatible.

## Build

### Prerequisites

- Rust with `wasm32-unknown-unknown`: `rustup target add wasm32-unknown-unknown`
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/): `cargo install wasm-pack`

### Build for Node.js

From the crate root:

```bash
wasm-pack build --target nodejs
```

Output: `pkg/` with `kontor_crypto_wasm.js`, `kontor_crypto_wasm_bg.wasm`, TypeScript definitions, and `package.json`.

### Build for browser (bundler / web)

```bash
wasm-pack build --target web
```

### Raw WASM (no JS glue)

From the workspace root:

```bash
cargo build -p kontor-crypto-wasm --target wasm32-unknown-unknown --release
```

Artifact: `target/wasm32-unknown-unknown/release/kontor_crypto_wasm.wasm`.

**Note:** If `wasm-pack` fails with a rustc version error when installing `wasm-bindgen-cli`, use the `cargo build` command above to produce only the `.wasm`; for full JS/TS bindings, use a Rust toolchain that matches the wasm-bindgen-cli requirement (e.g. rustc 1.82+ for wasm-bindgen 0.2.112) or pin `wasm-bindgen` to an older version in `Cargo.toml`.

## Binary size

Typical size for the `.wasm` is ~650 KB (release build). Check with:

```bash
wasm-pack build --target nodejs --release
ls -la pkg/*.wasm
```

## Performance

On first call, `prepareFile` initialises Poseidon constants (MDS matrix, round constants, sparse factorisation). This is a one-time cost cached for subsequent calls. On native targets this takes <10ms; in WASM it may take 50-200ms depending on the runtime. If cold-start latency matters, call `prepareFile` once with a small dummy input during app initialisation.

## Usage

### Node.js

After `wasm-pack build --target nodejs`:

```javascript
const path = require('path');
const { default: init, prepareFile } = require('./pkg/kontor_crypto_wasm.js');

async function run() {
  const wasmPath = path.join(__dirname, 'pkg', 'kontor_crypto_wasm_bg.wasm');
  await init(wasmPath);

  const file = new Uint8Array([104, 101, 108, 108, 111]); // "hello"
  const filename = 'test.txt';
  const nonce = new Uint8Array(0);

  const result = prepareFile(file, filename, nonce);
  console.log(result.metadata.root);       // hex string
  console.log(result.metadata.objectId);   // e.g. "obj_..."
  console.log(result.metadata.fileId);      // e.g. "file_..."
  console.log(result.preparedFile.treeLeavesHex);
  // Ready-to-send descriptor for filestorage.create_agreement:
  console.log(result.descriptor); // { fileId, objectId, nonce, root, paddedLen, originalSize, filename }
}
run();
```

### Browser

After `wasm-pack build --target web`, in your app:

```javascript
import init, { prepareFile } from './pkg/kontor_crypto_wasm.js';

await init(); // or init('./pkg/kontor_crypto_wasm_bg.wasm')

const file = new Uint8Array([...]); // file bytes
const result = prepareFile(file, 'filename.dat', new Uint8Array(0));
// result.metadata, result.preparedFile
```

### API

- **prepareFile(file, filename, nonce)**  
  - `file`: `Uint8Array` – raw file content  
  - `filename`: `string`  
  - `nonce`: `Uint8Array`  
  - Returns a JS object:
    - **metadata**: `{ root, objectId, fileId, nonce, paddedLen, originalSize, filename }`  
      - `root`: Merkle root as hex string  
    - **preparedFile**: `{ root, fileId, treeLeavesHex }`  
      - `treeLeavesHex`: array of hex strings (for prover)
    - **descriptor**: `{ fileId, objectId, nonce, root, paddedLen, originalSize, filename }`
      - `root`: 32-byte array (`Uint8Array` after serde-wasm-bindgen conversion)
      - Shape matches the `RawFileDescriptor` required by filestorage `create_agreement`.

Throws if input is empty or encoding fails.

## Test and example

- **Rust (host):** `cargo test -p kontor-crypto-wasm` – checks metadata shape and consistency with core.
- **Node example:** after `wasm-pack build --target nodejs`, from the crate directory:
  ```bash
  node examples/node_prepare_file.mjs
  ```
  Calls `prepareFile` with fixed input and asserts metadata and `preparedFile` shape and consistency.
- **Browser example:** after `wasm-pack build --target web`, serve the crate directory (e.g. `npx serve .` from `crates/kontor-crypto-wasm`) and open `examples/browser_prepare_file.html`. Verifies same metadata/preparedFile consistency from the browser.

## Package (npm)

The `pkg/` directory produced by `wasm-pack build` is a valid npm package. Publish or link it:

```bash
cd pkg && npm link
# or npm publish
```

TypeScript types are in `pkg/kontor_crypto_wasm.d.ts`.
