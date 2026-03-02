export type {
  PrepareResult,
  FileMetadata,
  PreparedFileData,
  RawFileDescriptor,
  OnProgress,
  ProgressPhase,
} from "./types.js";

import type {
  PrepareResult,
  FileMetadata,
  PreparedFileData,
  RawFileDescriptor,
  OnProgress,
} from "./types.js";

interface WasmModule {
  default: (wasmUrl?: string | URL) => Promise<unknown>;
  prepareLeaves: (
    file: Uint8Array,
    filename: string,
    nonce: Uint8Array
  ) => {
    leafBytes: Uint8Array;
    objectId: string;
    fileId: string;
    paddedLen: number;
    originalSize: number;
    filename: string;
    nonce: Uint8Array;
  };
  buildMerkleRoot: (leafBytes: Uint8Array) => Uint8Array;
  hashNodes: (left: Uint8Array, right: Uint8Array) => Uint8Array;
}

const wasmJsUrl = new URL("./kontor_crypto_wasm.js", import.meta.url).href;
const wasmBinUrl = new URL(
  "./kontor_crypto_wasm_bg.wasm",
  import.meta.url
).href;

let wasmMod: WasmModule | null = null;
let initPromise: Promise<void> | null = null;

export function init(): Promise<void> {
  if (!initPromise) {
    initPromise = (async () => {
      const mod: WasmModule = await import(wasmJsUrl);
      await mod.default(wasmBinUrl);
      wasmMod = mod;
    })();
    initPromise.catch(() => {
      initPromise = null;
    });
  }
  return initPromise;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function getWorkerCount(): number {
  let cores = 4;
  if (typeof navigator !== "undefined" && navigator.hardwareConcurrency) {
    cores = navigator.hardwareConcurrency;
  }
  const np2 = Math.pow(2, Math.floor(Math.log2(cores)));
  return Math.min(np2, 8);
}

function spawnWorker(): Worker {
  const code = `
    let _buildMerkleRoot;
    self.onmessage = async (e) => {
      if (e.data.type === 'init') {
        const mod = await import(e.data.jsUrl);
        await mod.default(e.data.wasmUrl);
        _buildMerkleRoot = mod.buildMerkleRoot;
        self.postMessage({ type: 'ready' });
      } else if (e.data.type === 'build') {
        try {
          const root = _buildMerkleRoot(e.data.leafBytes);
          self.postMessage({ type: 'result', root }, [root.buffer]);
        } catch (err) {
          self.postMessage({ type: 'error', message: String(err) });
        }
      }
    };
  `;
  const blob = new Blob([code], { type: "text/javascript" });
  return new Worker(URL.createObjectURL(blob), { type: "module" });
}

function runWorker(
  leafChunk: Uint8Array,
  jsUrl: string,
  wasmUrl: string
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const worker = spawnWorker();
    worker.onmessage = (ev: MessageEvent) => {
      if (ev.data.type === "ready") {
        worker.postMessage(
          { type: "build", leafBytes: leafChunk },
          [leafChunk.buffer]
        );
      } else if (ev.data.type === "result") {
        worker.terminate();
        resolve(ev.data.root);
      } else if (ev.data.type === "error") {
        worker.terminate();
        reject(new Error(ev.data.message));
      }
    };
    worker.onerror = (err) => {
      worker.terminate();
      reject(err);
    };
    worker.postMessage({ type: "init", jsUrl, wasmUrl });
  });
}

export async function prepareFile(
  file: File | Uint8Array | ArrayBuffer,
  filename?: string,
  nonce?: Uint8Array,
  onProgress?: OnProgress
): Promise<PrepareResult> {
  await init();
  const mod = wasmMod!;
  onProgress?.(0, 'reading');

  let bytes: Uint8Array;
  if (file instanceof Uint8Array) {
    bytes = file;
  } else if (file instanceof ArrayBuffer) {
    bytes = new Uint8Array(file);
  } else {
    bytes = new Uint8Array(await file.arrayBuffer());
    if (!filename) filename = file.name;
  }

  if (!filename) filename = "untitled";
  if (!nonce) nonce = new Uint8Array(0);

  onProgress?.(0.05, 'encoding');
  await new Promise((r) => setTimeout(r, 0));

  const prep = mod.prepareLeaves(bytes, filename, nonce);
  const leafBytes = prep.leafBytes;
  const leavesCount = leafBytes.length / 32;

  onProgress?.(0.15, 'merkle');

  const workerCount = Math.min(getWorkerCount(), leavesCount);
  const chunkSize = leavesCount / workerCount;

  const promises: Promise<Uint8Array>[] = [];
  for (let i = 0; i < workerCount; i++) {
    const start = i * chunkSize * 32;
    const end = (i + 1) * chunkSize * 32;
    promises.push(runWorker(leafBytes.slice(start, end), wasmJsUrl, wasmBinUrl));
  }

  const results: Uint8Array[] = new Array(workerCount);
  let completed = 0;
  await Promise.all(
    promises.map((p, i) =>
      p.then((root) => {
        results[i] = root;
        completed++;
        onProgress?.(0.15 + 0.75 * (completed / workerCount), 'merkle');
      })
    )
  );
  let roots = results;

  while (roots.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < roots.length; i += 2) {
      next.push(mod.hashNodes(roots[i], roots[i + 1]));
    }
    roots = next;
  }

  const rootBytes = roots[0];
  const rootHex = bytesToHex(rootBytes);

  const treeLeavesHex: string[] = [];
  for (let i = 0; i < leavesCount; i++) {
    treeLeavesHex.push(bytesToHex(leafBytes.subarray(i * 32, (i + 1) * 32)));
  }

  const metadata: FileMetadata = {
    root: rootHex,
    objectId: prep.objectId,
    fileId: prep.fileId,
    nonce: Array.from(prep.nonce),
    paddedLen: prep.paddedLen,
    originalSize: prep.originalSize,
    filename: prep.filename,
  };

  const preparedFile: PreparedFileData = {
    root: rootHex,
    fileId: prep.fileId,
    treeLeavesHex,
  };

  const descriptor: RawFileDescriptor = {
    fileId: prep.fileId,
    objectId: prep.objectId,
    nonce: Array.from(prep.nonce),
    root: Array.from(rootBytes),
    paddedLen: prep.paddedLen,
    originalSize: prep.originalSize,
    filename: prep.filename,
  };

  onProgress?.(1, 'finalizing');

  return { metadata, preparedFile, descriptor };
}
