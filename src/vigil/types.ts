export type EvidenceStatus = 'verified' | 'pass' | 'finding' | 'unknown' | 'running' | 'not-run';

export type RiskLevel = 'low' | 'moderate' | 'high' | 'critical' | 'unknown';

export interface TensorRecord {
    name: string;
    dtype: string;
    shape: number[];
    byteStart: number;
    byteEnd: number;
    bytes: number;
    category: TensorCategory;
    chunkStart?: number;
    chunkEnd?: number;
}

export type TensorCategory = 'embedding' | 'attention' | 'feed-forward' | 'normalization' | 'output' | 'other';

export interface MerkleLeaf {
    index: number;
    offset: number;
    length: number;
    hash: string;
}

export interface ArtifactAnalysis {
    fileName: string;
    format: 'safetensors' | 'gguf' | 'unknown';
    fileSize: number;
    architecture: string;
    tensorCount: number;
    tensors: TensorRecord[];
    metadata: Record<string, string | number | boolean>;
    chunkSize: number;
    leaves: MerkleLeaf[];
    merkleRoot: string;
    analyzedAt: string;
}

export interface ScanCheck {
    id: string;
    title: string;
    detail: string;
    status: EvidenceStatus;
    risk: RiskLevel;
    evidence: string;
}

export interface ToolTrace {
    id: string;
    time: string;
    tool: string;
    action: string;
    target: string;
    decision: 'allowed' | 'blocked' | 'approval-required';
    reason: string;
    taint: string[];
    impact: string;
}
