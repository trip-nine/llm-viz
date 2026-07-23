import { ArtifactAnalysis, MerkleLeaf, TensorCategory, TensorRecord } from './types';

const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;
const MAX_HEADER_BYTES = 64 * 1024 * 1024;

export type AnalysisProgress = {
    stage: 'metadata' | 'hashing' | 'finalizing';
    fraction: number;
    message: string;
};

type ProgressCallback = (progress: AnalysisProgress) => void;

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

const SHA256_CONSTANTS = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotateRight(value: number, bits: number): number {
    return (value >>> bits) | (value << (32 - bits));
}

export function sha256Fallback(bytes: Uint8Array): Uint8Array {
    const bitLength = BigInt(bytes.length) * 8n;
    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const paddedView = new DataView(padded.buffer);
    paddedView.setUint32(paddedLength - 8, Number((bitLength >> 32n) & 0xffffffffn), false);
    paddedView.setUint32(paddedLength - 4, Number(bitLength & 0xffffffffn), false);

    const state = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const words = new Uint32Array(64);

    for (let offset = 0; offset < paddedLength; offset += 64) {
        for (let index = 0; index < 16; index += 1) {
            words[index] = paddedView.getUint32(offset + index * 4, false);
        }
        for (let index = 16; index < 64; index += 1) {
            const s0 = rotateRight(words[index - 15], 7) ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >>> 3);
            const s1 = rotateRight(words[index - 2], 17) ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >>> 10);
            words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
        }

        let [a, b, c, d, e, f, g, h] = state;
        for (let index = 0; index < 64; index += 1) {
            const sigma1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const choice = (e & f) ^ (~e & g);
            const temporary1 = (h + sigma1 + choice + SHA256_CONSTANTS[index] + words[index]) >>> 0;
            const sigma0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const majority = (a & b) ^ (a & c) ^ (b & c);
            const temporary2 = (sigma0 + majority) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temporary1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temporary1 + temporary2) >>> 0;
        }

        state[0] = (state[0] + a) >>> 0;
        state[1] = (state[1] + b) >>> 0;
        state[2] = (state[2] + c) >>> 0;
        state[3] = (state[3] + d) >>> 0;
        state[4] = (state[4] + e) >>> 0;
        state[5] = (state[5] + f) >>> 0;
        state[6] = (state[6] + g) >>> 0;
        state[7] = (state[7] + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const resultView = new DataView(result.buffer);
    state.forEach((word, index) => resultView.setUint32(index * 4, word, false));
    return result;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
    if (globalThis.crypto?.subtle) {
        const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
        return new Uint8Array(digest);
    }
    return sha256Fallback(bytes);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}

async function merkleRootFromHashes(hashes: Uint8Array[]): Promise<Uint8Array> {
    if (hashes.length === 0) {
        return sha256(new Uint8Array());
    }

    async function subtree(start: number, count: number): Promise<Uint8Array> {
        if (count === 1) return hashes[start];
        let split = 1;
        while ((split << 1) < count) split <<= 1;
        const [left, right] = await Promise.all([
            subtree(start, split),
            subtree(start + split, count - split),
        ]);
        return sha256(concatBytes(new Uint8Array([1]), left, right));
    }

    return subtree(0, hashes.length);
}

function categorizeTensor(name: string): TensorCategory {
    const normalized = name.toLowerCase();
    if (/embed|token_embd|tok_embeddings/.test(normalized)) return 'embedding';
    if (/attn|attention|query|key|value|q_proj|k_proj|v_proj|o_proj/.test(normalized)) return 'attention';
    if (/ffn|feed_forward|mlp|gate_proj|up_proj|down_proj/.test(normalized)) return 'feed-forward';
    if (/norm|ln_|layernorm/.test(normalized)) return 'normalization';
    if (/output|lm_head/.test(normalized)) return 'output';
    return 'other';
}

function safeNumber(value: bigint, label: string): number {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`${label} is too large to index safely in this browser.`);
    }
    return Number(value);
}

async function parseSafetensors(file: File): Promise<Pick<ArtifactAnalysis, 'format' | 'architecture' | 'tensors' | 'metadata'>> {
    if (file.size < 8) throw new Error('The Safetensors file is too small to contain a header.');
    const prefix = new DataView(await file.slice(0, 8).arrayBuffer());
    const headerLength = safeNumber(prefix.getBigUint64(0, true), 'Safetensors header');
    if (headerLength <= 0 || headerLength > MAX_HEADER_BYTES || 8 + headerLength > file.size) {
        throw new Error('The Safetensors header length is invalid or exceeds the 64 MiB safety limit.');
    }

    const headerText = new TextDecoder().decode(await file.slice(8, 8 + headerLength).arrayBuffer());
    type SafetensorsEntry = { dtype?: string; shape?: number[]; data_offsets?: number[] };
    const header = JSON.parse(headerText) as Record<string, SafetensorsEntry | Record<string, string>>;
    const rawMetadata = (header.__metadata__ ?? {}) as Record<string, string>;
    const dataStart = 8 + headerLength;
    const tensors: TensorRecord[] = [];

    for (const [name, value] of Object.entries(header)) {
        if (name === '__metadata__') continue;
        const tensor = value as SafetensorsEntry;
        if (!Array.isArray(tensor.data_offsets) || tensor.data_offsets.length !== 2) continue;
        const [relativeStart, relativeEnd] = tensor.data_offsets;
        if (!Number.isFinite(relativeStart) || !Number.isFinite(relativeEnd) || relativeStart < 0 || relativeEnd < relativeStart) {
            throw new Error(`Tensor ${name} contains invalid byte offsets.`);
        }
        const byteStart = dataStart + relativeStart;
        const byteEnd = dataStart + relativeEnd;
        if (byteEnd > file.size) throw new Error(`Tensor ${name} extends beyond the end of the file.`);
        tensors.push({
            name,
            dtype: tensor.dtype ?? 'unknown',
            shape: tensor.shape ?? [],
            byteStart,
            byteEnd,
            bytes: byteEnd - byteStart,
            category: categorizeTensor(name),
        });
    }

    tensors.sort((a, b) => a.byteStart - b.byteStart);
    const architecture = rawMetadata.architecture ?? rawMetadata.model_type ?? inferArchitecture(tensors.map(tensor => tensor.name));
    const metadata: Record<string, string | number | boolean> = {
        ...rawMetadata,
        header_bytes: headerLength,
        data_bytes: file.size - dataStart,
    };
    return { format: 'safetensors', architecture, tensors, metadata };
}

class GgufReader {
    private view: DataView;
    private cursor = 0;
    private decoder = new TextDecoder();

    constructor(buffer: ArrayBuffer) {
        this.view = new DataView(buffer);
    }

    get offset(): number { return this.cursor; }

    ensure(length: number) {
        if (this.cursor + length > this.view.byteLength) {
            throw new Error('GGUF metadata exceeds the 64 MiB browser preview limit. Use the worker/CLI analyzer for this artifact.');
        }
    }

    u8(): number { this.ensure(1); const value = this.view.getUint8(this.cursor); this.cursor += 1; return value; }
    i8(): number { this.ensure(1); const value = this.view.getInt8(this.cursor); this.cursor += 1; return value; }
    u16(): number { this.ensure(2); const value = this.view.getUint16(this.cursor, true); this.cursor += 2; return value; }
    i16(): number { this.ensure(2); const value = this.view.getInt16(this.cursor, true); this.cursor += 2; return value; }
    u32(): number { this.ensure(4); const value = this.view.getUint32(this.cursor, true); this.cursor += 4; return value; }
    i32(): number { this.ensure(4); const value = this.view.getInt32(this.cursor, true); this.cursor += 4; return value; }
    f32(): number { this.ensure(4); const value = this.view.getFloat32(this.cursor, true); this.cursor += 4; return value; }
    u64(): bigint { this.ensure(8); const value = this.view.getBigUint64(this.cursor, true); this.cursor += 8; return value; }
    i64(): bigint { this.ensure(8); const value = this.view.getBigInt64(this.cursor, true); this.cursor += 8; return value; }
    f64(): number { this.ensure(8); const value = this.view.getFloat64(this.cursor, true); this.cursor += 8; return value; }

    string(): string {
        const length = safeNumber(this.u64(), 'GGUF string');
        this.ensure(length);
        const value = this.decoder.decode(new Uint8Array(this.view.buffer, this.cursor, length));
        this.cursor += length;
        return value;
    }

    value(type: number, depth = 0): unknown {
        if (depth > 4) throw new Error('GGUF metadata nesting is unexpectedly deep.');
        switch (type) {
            case 0: return this.u8();
            case 1: return this.i8();
            case 2: return this.u16();
            case 3: return this.i16();
            case 4: return this.u32();
            case 5: return this.i32();
            case 6: return this.f32();
            case 7: return Boolean(this.u8());
            case 8: return this.string();
            case 9: {
                const itemType = this.u32();
                const length = safeNumber(this.u64(), 'GGUF array');
                const preview: unknown[] = [];
                for (let index = 0; index < length; index++) {
                    const item = this.value(itemType, depth + 1);
                    if (preview.length < 16) preview.push(item);
                }
                return length <= 16 ? preview : `[${length} values]`;
            }
            case 10: return safeNumber(this.u64(), 'GGUF uint64 value');
            case 11: return Number(this.i64());
            case 12: return this.f64();
            default: throw new Error(`Unsupported GGUF metadata type ${type}.`);
        }
    }
}

const GGML_TYPES: Record<number, string> = {
    0: 'F32', 1: 'F16', 2: 'Q4_0', 3: 'Q4_1', 6: 'Q5_0', 7: 'Q5_1', 8: 'Q8_0', 9: 'Q8_1',
    10: 'Q2_K', 11: 'Q3_K', 12: 'Q4_K', 13: 'Q5_K', 14: 'Q6_K', 15: 'Q8_K', 16: 'IQ2_XXS',
    17: 'IQ2_XS', 18: 'IQ3_XXS', 19: 'IQ1_S', 20: 'IQ4_NL', 21: 'IQ3_S', 22: 'IQ2_S',
    23: 'IQ4_XS', 24: 'I8', 25: 'I16', 26: 'I32', 27: 'I64', 28: 'F64', 29: 'IQ1_M', 30: 'BF16',
};

async function parseGguf(file: File): Promise<Pick<ArtifactAnalysis, 'format' | 'architecture' | 'tensors' | 'metadata'>> {
    const previewBytes = Math.min(file.size, MAX_HEADER_BYTES);
    const reader = new GgufReader(await file.slice(0, previewBytes).arrayBuffer());
    const magic = String.fromCharCode(reader.u8(), reader.u8(), reader.u8(), reader.u8());
    if (magic !== 'GGUF') throw new Error('The selected file does not contain a GGUF header.');
    const version = reader.u32();
    const tensorCount = safeNumber(reader.u64(), 'GGUF tensor count');
    const metadataCount = safeNumber(reader.u64(), 'GGUF metadata count');
    if (tensorCount > 5_000_000 || metadataCount > 1_000_000) throw new Error('GGUF index counts exceed safety limits.');

    const metadata: Record<string, string | number | boolean> = { gguf_version: version };
    let alignment = 32;
    for (let index = 0; index < metadataCount; index++) {
        const key = reader.string();
        const value = reader.value(reader.u32());
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
            metadata[key] = value;
            if (key === 'general.alignment' && typeof value === 'number') alignment = value;
        }
    }

    const rawTensors: Array<{ name: string; shape: number[]; dtype: string; offset: number }> = [];
    for (let index = 0; index < tensorCount; index++) {
        const name = reader.string();
        const dimensions = reader.u32();
        if (dimensions > 16) throw new Error(`Tensor ${name} declares too many dimensions.`);
        const shape = Array.from({ length: dimensions }, () => safeNumber(reader.u64(), `Tensor ${name} dimension`));
        const type = reader.u32();
        const offset = safeNumber(reader.u64(), `Tensor ${name} offset`);
        rawTensors.push({ name, shape, dtype: GGML_TYPES[type] ?? `GGML_${type}`, offset });
    }

    const tensorDataStart = Math.ceil(reader.offset / alignment) * alignment;
    const byOffset = [...rawTensors].sort((a, b) => a.offset - b.offset);
    const tensors = byOffset.map((tensor, index): TensorRecord => {
        const byteStart = tensorDataStart + tensor.offset;
        const nextStart = index + 1 < byOffset.length ? tensorDataStart + byOffset[index + 1].offset : file.size;
        const byteEnd = Math.min(file.size, Math.max(byteStart, nextStart));
        return {
            name: tensor.name,
            dtype: tensor.dtype,
            shape: tensor.shape,
            byteStart,
            byteEnd,
            bytes: byteEnd - byteStart,
            category: categorizeTensor(tensor.name),
        };
    });

    metadata.header_bytes = tensorDataStart;
    metadata.data_bytes = file.size - tensorDataStart;
    const architectureValue = metadata['general.architecture'];
    const architecture = typeof architectureValue === 'string' ? architectureValue : inferArchitecture(tensors.map(tensor => tensor.name));
    return { format: 'gguf', architecture, tensors, metadata };
}

function inferArchitecture(names: string[]): string {
    const joined = names.slice(0, 100).join(' ').toLowerCase();
    if (joined.includes('llama') || joined.includes('blk.')) return 'decoder transformer';
    if (joined.includes('encoder') && joined.includes('decoder')) return 'encoder-decoder transformer';
    if (joined.includes('bert')) return 'encoder transformer';
    return 'transformer';
}

async function hashArtifact(file: File, chunkSize: number, onProgress?: ProgressCallback): Promise<{ leaves: MerkleLeaf[]; root: string }> {
    const leafHashes: Uint8Array[] = [];
    const leaves: MerkleLeaf[] = [];
    const totalChunks = Math.max(1, Math.ceil(file.size / chunkSize));
    const encoder = new TextEncoder();

    for (let index = 0; index < totalChunks; index++) {
        const offset = index * chunkSize;
        const length = Math.min(chunkSize, file.size - offset);
        const chunk = new Uint8Array(await file.slice(offset, offset + length).arrayBuffer());
        const envelope = encoder.encode(`vigil-chunk-v1\n${file.name}\n${file.size}\n${index}\n${offset}\n${length}\n`);
        const leafHash = await sha256(concatBytes(new Uint8Array([0]), envelope, chunk));
        leafHashes.push(leafHash);
        leaves.push({ index, offset, length, hash: bytesToHex(leafHash) });
        onProgress?.({
            stage: 'hashing',
            fraction: (index + 1) / totalChunks,
            message: `Hashed chunk ${index + 1} of ${totalChunks}`,
        });
        if (index % 8 === 0) await new Promise(resolve => setTimeout(resolve, 0));
    }

    onProgress?.({ stage: 'finalizing', fraction: 1, message: 'Building domain-separated Merkle root' });
    return { leaves, root: bytesToHex(await merkleRootFromHashes(leafHashes)) };
}

export async function analyzeLocalArtifact(
    file: File,
    onProgress?: ProgressCallback,
    chunkSize = DEFAULT_CHUNK_SIZE,
): Promise<ArtifactAnalysis> {
    onProgress?.({ stage: 'metadata', fraction: 0, message: 'Reading model metadata without executing it' });
    const lowerName = file.name.toLowerCase();
    const parsed = lowerName.endsWith('.safetensors')
        ? await parseSafetensors(file)
        : lowerName.endsWith('.gguf')
            ? await parseGguf(file)
            : { format: 'unknown' as const, architecture: 'unknown', tensors: [], metadata: {} };

    const tensors = parsed.tensors.map(tensor => ({
        ...tensor,
        chunkStart: Math.floor(tensor.byteStart / chunkSize),
        chunkEnd: Math.floor(Math.max(tensor.byteStart, tensor.byteEnd - 1) / chunkSize),
    }));
    onProgress?.({ stage: 'metadata', fraction: 1, message: `Indexed ${tensors.length.toLocaleString()} tensors` });
    const hashed = await hashArtifact(file, chunkSize, onProgress);

    return {
        fileName: file.name,
        format: parsed.format,
        fileSize: file.size,
        architecture: parsed.architecture,
        tensorCount: tensors.length,
        tensors,
        metadata: parsed.metadata,
        chunkSize,
        leaves: hashed.leaves,
        merkleRoot: hashed.root,
        analyzedAt: new Date().toISOString(),
    };
}

export function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const order = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
    const value = bytes / (1024 ** order);
    return `${value >= 10 || order === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[order]}`;
}
