export interface FileMetadata {
  root: string;
  objectId: string;
  fileId: string;
  nonce: number[];
  paddedLen: number;
  originalSize: number;
  filename: string;
}

export interface PreparedFileData {
  root: string;
  fileId: string;
  treeLeavesHex: string[];
}

export interface RawFileDescriptor {
  fileId: string;
  objectId: string;
  nonce: number[];
  root: number[];
  paddedLen: number;
  originalSize: number;
  filename: string;
}

export interface PrepareResult {
  metadata: FileMetadata;
  preparedFile: PreparedFileData;
  descriptor: RawFileDescriptor;
}

export type ProgressPhase = 'reading' | 'encoding' | 'merkle' | 'finalizing';
export type OnProgress = (progress: number, phase: ProgressPhase) => void;
