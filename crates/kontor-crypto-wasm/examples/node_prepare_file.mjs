#!/usr/bin/env node
/**
 * Node example: call prepareFile from JS and assert metadata shape and consistency.
 * Run after: wasm-pack build --target nodejs
 * From crate dir: node examples/node_prepare_file.mjs
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const pkgDir = path.join(__dirname, '..', 'pkg');
  const wasmPath = path.join(pkgDir, 'kontor_crypto_wasm_bg.wasm');
  const moduleUrl = new URL('../pkg/kontor_crypto_wasm.js', import.meta.url).href;
  const { default: init, prepareFile } = await import(moduleUrl);
  await init(wasmPath);

  const file = new Uint8Array([104, 101, 108, 108, 111]); // "hello"
  const filename = 'test.txt';
  const nonce = new Uint8Array(0);

  const result = prepareFile(file, filename, nonce);
  if (result === undefined) throw new Error('prepareFile returned undefined');
  const obj = result;

  if (!obj.metadata) throw new Error('missing metadata');
  const { metadata, preparedFile } = obj;
  if (!metadata.root || typeof metadata.root !== 'string') throw new Error('metadata.root must be a non-empty string');
  if (!metadata.objectId || !metadata.objectId.startsWith('obj_')) throw new Error('metadata.objectId must start with obj_');
  if (!metadata.fileId || !metadata.fileId.startsWith('file_')) throw new Error('metadata.fileId must start with file_');
  if (metadata.originalSize !== 5) throw new Error('metadata.originalSize should be 5');
  if (metadata.filename !== 'test.txt') throw new Error('metadata.filename should be test.txt');

  if (!preparedFile) throw new Error('missing preparedFile');
  if (preparedFile.root !== metadata.root) throw new Error('preparedFile.root must match metadata.root');
  if (preparedFile.fileId !== metadata.fileId) throw new Error('preparedFile.fileId must match metadata.fileId');
  if (!Array.isArray(preparedFile.treeLeavesHex) || preparedFile.treeLeavesHex.length === 0) {
    throw new Error('preparedFile.treeLeavesHex must be a non-empty array');
  }

  // Descriptor for filestorage.create_agreement
  const { descriptor } = obj;
  if (!descriptor) throw new Error('missing descriptor');
  if (descriptor.fileId !== metadata.fileId) throw new Error('descriptor.fileId must match metadata.fileId');
  if (descriptor.objectId !== metadata.objectId) throw new Error('descriptor.objectId must match metadata.objectId');
  if (descriptor.filename !== metadata.filename) throw new Error('descriptor.filename must match metadata.filename');
  if (descriptor.originalSize !== metadata.originalSize) throw new Error('descriptor.originalSize must match metadata.originalSize');
  if (descriptor.paddedLen !== metadata.paddedLen) throw new Error('descriptor.paddedLen must match metadata.paddedLen');
  if (!Array.isArray(descriptor.root) || descriptor.root.length !== 32) {
    throw new Error('descriptor.root must be a 32-byte array');
  }

  console.log('prepareFile OK');
  console.log('  metadata.root (hex):', metadata.root.slice(0, 24) + '...');
  console.log('  metadata.objectId:', metadata.objectId);
  console.log('  metadata.fileId:', metadata.fileId);
  console.log('  metadata.originalSize:', metadata.originalSize);
  console.log('  preparedFile.treeLeavesHex.length:', preparedFile.treeLeavesHex.length);
  console.log('  descriptor.root.length:', descriptor.root.length);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
