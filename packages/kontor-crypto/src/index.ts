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

const HEX: string[] = [];
for (let i = 0; i < 256; i++) HEX[i] = i.toString(16).padStart(2, "0");

/** Encode a 32-byte field element repr as big-endian hex (MSB-first),
 *  matching Rust `field_to_hex` which iterates `.iter().rev()`. */
function fieldBytesToHex(bytes: Uint8Array, offset = 0, len = 32): string {
  let hex = "";
  for (let j = offset + len - 1; j >= offset; j--) hex += HEX[bytes[j]];
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

function spawnWorker(): { worker: Worker; blobUrl: string } {
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
  const blobUrl = URL.createObjectURL(blob);
  return { worker: new Worker(blobUrl, { type: "module" }), blobUrl };
}

interface WorkerPool {
  dispatch(leafBytes: Uint8Array): Promise<Uint8Array>;
  terminate(): void;
}

function createWorkerPool(
  size: number,
  jsUrl: string,
  wasmUrl: string
): Promise<WorkerPool> {
  return new Promise((resolvePool, rejectPool) => {
    const workers: { worker: Worker; blobUrl: string }[] = [];
    const freeWorkers: Worker[] = [];
    const pendingTasks = new Map<
      Worker,
      { resolve: (root: Uint8Array) => void; reject: (err: Error) => void }
    >();
    const taskQueue: {
      leafBytes: Uint8Array;
      resolve: (root: Uint8Array) => void;
      reject: (err: Error) => void;
    }[] = [];
    let readyCount = 0;
    let initFailed = false;

    function recycleWorker(w: Worker) {
      const next = taskQueue.shift();
      if (next) {
        pendingTasks.set(w, { resolve: next.resolve, reject: next.reject });
        w.postMessage(
          { type: "build", leafBytes: next.leafBytes },
          [next.leafBytes.buffer]
        );
      } else {
        freeWorkers.push(w);
      }
    }

    for (let i = 0; i < size; i++) {
      const entry = spawnWorker();
      workers.push(entry);
      const w = entry.worker;

      w.onmessage = (ev: MessageEvent) => {
        if (ev.data.type === "ready") {
          freeWorkers.push(w);
          readyCount++;
          if (readyCount === size) {
            resolvePool({
              dispatch(leafBytes: Uint8Array): Promise<Uint8Array> {
                return new Promise((resolve, reject) => {
                  const worker = freeWorkers.pop();
                  if (worker) {
                    pendingTasks.set(worker, { resolve, reject });
                    worker.postMessage(
                      { type: "build", leafBytes },
                      [leafBytes.buffer]
                    );
                  } else {
                    taskQueue.push({ leafBytes, resolve, reject });
                  }
                });
              },
              terminate() {
                workers.forEach((e) => {
                  URL.revokeObjectURL(e.blobUrl);
                  e.worker.terminate();
                });
              },
            });
          }
        } else if (ev.data.type === "result") {
          const pending = pendingTasks.get(w)!;
          pendingTasks.delete(w);
          pending.resolve(ev.data.root);
          recycleWorker(w);
        } else if (ev.data.type === "error") {
          const pending = pendingTasks.get(w)!;
          pendingTasks.delete(w);
          pending.reject(new Error(ev.data.message));
          recycleWorker(w);
        }
      };

      w.onerror = (err) => {
        if (readyCount < size && !initFailed) {
          initFailed = true;
          workers.forEach((e) => {
            URL.revokeObjectURL(e.blobUrl);
            e.worker.terminate();
          });
          rejectPool(new Error(`Worker init failed: ${String(err)}`));
          return;
        }
        // Remove dead worker from free pool to prevent dispatching to it.
        const idx = freeWorkers.indexOf(w);
        if (idx >= 0) freeWorkers.splice(idx, 1);
        const pending = pendingTasks.get(w);
        if (pending) {
          pendingTasks.delete(w);
          pending.reject(new Error(String(err)));
        }
      };

      w.postMessage({ type: "init", jsUrl, wasmUrl });
    }
  });
}

function chooseBatchCount(leavesCount: number): number {
  if (leavesCount >= 65536) return 128;
  if (leavesCount >= 16384) return 64;
  if (leavesCount >= 256) return 32;
  // leavesCount is always a power of two (>= 256) from the prepare_file
  // pipeline, so this branch is only hit in hypothetical edge cases.
  return 1;
}

function readFileWithProgress(
  file: File,
  onProgress?: (ratio: number) => void
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onprogress = (e) => {
      if (e.lengthComputable) onProgress?.(e.loaded / e.total);
    };
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

const PHASE_READING = 0.05;
const PHASE_ENCODING = 0.15;
const PHASE_MERKLE = 0.90;

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
    bytes = await readFileWithProgress(file, (ratio) => {
      onProgress?.(PHASE_READING * ratio, 'reading');
    });
    if (!filename) filename = file.name;
  }

  if (!filename) filename = "untitled";
  if (!nonce) nonce = new Uint8Array(0);

  // Workers load WASM in background threads while prepareLeaves runs on main
  const poolPromise = createWorkerPool(getWorkerCount(), wasmJsUrl, wasmBinUrl);

  onProgress?.(PHASE_READING, 'encoding');
  await new Promise((r) => setTimeout(r, 0));

  let pool: WorkerPool | undefined;
  try {
    const prep = mod.prepareLeaves(bytes, filename, nonce);
    const leafBytes = prep.leafBytes;
    const leavesCount = leafBytes.length / 32;

    onProgress?.(PHASE_ENCODING, 'merkle');

    pool = await poolPromise;
    const batchCount = chooseBatchCount(leavesCount);
    const batchSize = leavesCount / batchCount;

    const merkleRange = PHASE_MERKLE - PHASE_ENCODING;
    let completed = 0;

    const subRoots = new Array<Uint8Array>(batchCount);
    await Promise.all(
      Array.from({ length: batchCount }, (_, i) => {
        const start = i * batchSize * 32;
        const end = (i + 1) * batchSize * 32;
        return pool!.dispatch(leafBytes.slice(start, end)).then((root) => {
          subRoots[i] = root;
          completed++;
          onProgress?.(
            PHASE_ENCODING + merkleRange * (completed / batchCount),
            'merkle'
          );
        });
      })
    );

    let roots: Uint8Array[] = subRoots;

    if (roots.length > 1 && (roots.length & (roots.length - 1)) !== 0) {
      throw new Error(
        `internal: sub-root count must be a power of two, got ${roots.length}`
      );
    }

    while (roots.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < roots.length; i += 2) {
        next.push(mod.hashNodes(roots[i], roots[i + 1]));
      }
      roots = next;
    }

    const rootBytes = roots[0];
    const rootHex = fieldBytesToHex(rootBytes);

    const treeLeavesHex: string[] = new Array(leavesCount);
    const hexBatchSize = 8192;
    const finalRange = 1 - PHASE_MERKLE;

    for (let batch = 0; batch < leavesCount; batch += hexBatchSize) {
      const end = Math.min(batch + hexBatchSize, leavesCount);
      for (let i = batch; i < end; i++) {
        treeLeavesHex[i] = fieldBytesToHex(leafBytes, i * 32);
      }
      onProgress?.(
        PHASE_MERKLE +
          finalRange * Math.min((batch + hexBatchSize) / leavesCount, 1),
        'finalizing'
      );
      if (end < leavesCount) {
        await new Promise((r) => setTimeout(r, 0));
      }
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
  } finally {
    if (pool) {
      pool.terminate();
    } else {
      poolPromise.then((p) => p.terminate()).catch(() => {});
    }
  }
}
