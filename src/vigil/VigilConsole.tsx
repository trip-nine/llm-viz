'use client';

import React, { ChangeEvent, useEffect, useMemo, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
    faArrowLeft,
    faArrowRight,
    faBell,
    faBolt,
    faCheck,
    faChevronDown,
    faChevronRight,
    faCircleExclamation,
    faCircleInfo,
    faClockRotateLeft,
    faCodeBranch,
    faCube,
    faDatabase,
    faDownload,
    faFileShield,
    faFingerprint,
    faFlask,
    faGaugeHigh,
    faLink,
    faLock,
    faMagnifyingGlass,
    faPause,
    faPlay,
    faRotate,
    faShieldHalved,
    faSliders,
    faTerminal,
    faTriangleExclamation,
    faUpload,
    faWrench,
    faXmark,
} from '@fortawesome/free-solid-svg-icons';
import clsx from 'clsx';
import s from './VigilConsole.module.scss';
import { analyzeLocalArtifact, AnalysisProgress, formatBytes } from './artifactAnalysis';
import {
    DYNAMIC_SUITES,
    EVALUATION_CASES,
    MERKLE_SAMPLE,
    MODEL_CATEGORIES,
    MODEL_NAME,
    STATIC_CHECKS,
    TOOL_TRACES,
    TRANSFORMER_BLOCKS,
} from './modelData';
import { ArtifactAnalysis, EvidenceStatus, TensorCategory, ToolTrace } from './types';

type ConsoleTab = 'visualize' | 'static' | 'dynamic' | 'tools' | 'integrity' | 'monitor' | 'decision';
type MapMode = '3d' | 'category' | 'integrity' | 'diff';

const TABS: Array<{ id: ConsoleTab; label: string; icon: typeof faCube }> = [
    { id: 'visualize', label: 'Visualize', icon: faCube },
    { id: 'static', label: 'Static', icon: faFingerprint },
    { id: 'dynamic', label: 'Dynamic', icon: faFlask },
    { id: 'tools', label: 'Tools', icon: faWrench },
    { id: 'integrity', label: 'Integrity', icon: faFileShield },
    { id: 'monitor', label: 'Monitor', icon: faGaugeHigh },
    { id: 'decision', label: 'Decision', icon: faShieldHalved },
];

const SIDE_LINKS: Array<{ id: ConsoleTab; label: string; code: string }> = [
    { id: 'visualize', label: 'Overview', code: 'W1' },
    { id: 'static', label: 'Static analysis', code: 'W2' },
    { id: 'dynamic', label: 'Dynamic analysis', code: 'W3' },
    { id: 'tools', label: 'Tool integrity', code: 'W4' },
    { id: 'integrity', label: 'Integrity log', code: 'W5' },
    { id: 'monitor', label: 'Model monitoring', code: 'W6' },
    { id: 'decision', label: 'Decision report', code: 'W7' },
];

const MOCK_TENSORS = [
    'attn_q.weight', 'attn_k.weight', 'attn_v.weight', 'attn_output.weight',
    'ffn_gate.weight', 'ffn_up.weight', 'ffn_down.weight', 'attn_norm.weight',
    'ffn_norm.weight', 'rope_freqs.weight', 'q_norm.weight', 'k_norm.weight',
    'residual_scale', 'quant_scale',
];

const STATUS_LABELS: Record<EvidenceStatus, string> = {
    verified: 'Verified',
    pass: 'No finding',
    finding: 'Finding',
    unknown: 'Unknown',
    running: 'Running',
    'not-run': 'Not run',
};

function StatusPill({ status, children }: { status: EvidenceStatus | 'blocked' | 'approval' | 'cached'; children?: React.ReactNode }) {
    const icon = status === 'finding' || status === 'blocked'
        ? faTriangleExclamation
        : status === 'unknown' || status === 'not-run' || status === 'approval'
            ? faCircleInfo
            : status === 'running'
                ? faRotate
                : faCheck;
    return <span className={clsx(s.statusPill, s[`status_${status}`])}>
        <FontAwesomeIcon icon={icon} spin={status === 'running'} />
        {children ?? (status in STATUS_LABELS ? STATUS_LABELS[status as EvidenceStatus] : status)}
    </span>;
}

function EvidenceBadge({ tone, children }: { tone: 'green' | 'blue' | 'amber' | 'slate'; children: React.ReactNode }) {
    return <span className={clsx(s.evidenceBadge, s[`badge_${tone}`])}>{children}</span>;
}

function formatHash(hash: string, start = 12, end = 10) {
    if (!hash) return 'not computed';
    if (hash.length <= start + end + 3) return hash;
    return `${hash.slice(0, start)}…${hash.slice(-end)}`;
}

function normalizeModelReference(value: string): string {
    const trimmed = value.trim().replace(/\/$/, '');
    const huggingFaceMatch = trimmed.match(/huggingface\.co\/([^/]+\/[^/?#]+)/i);
    if (huggingFaceMatch) return huggingFaceMatch[1].replace(/\/(tree|resolve)\/.+$/, '');
    const ollamaMatch = trimmed.match(/ollama:\/\/([^\s]+)/i);
    if (ollamaMatch) return ollamaMatch[1];
    return trimmed || MODEL_NAME;
}

function categoryColor(category: TensorCategory): string {
    switch (category) {
        case 'feed-forward': return 'teal';
        case 'attention': return 'green';
        case 'embedding': return 'blue';
        case 'normalization': return 'amber';
        case 'output': return 'violet';
        default: return 'slate';
    }
}

export function VigilConsole() {
    const [activeTab, setActiveTab] = useState<ConsoleTab>('visualize');
    const [mapMode, setMapMode] = useState<MapMode>('3d');
    const [modelName, setModelName] = useState(MODEL_NAME);
    const [modelReference, setModelReference] = useState(MODEL_NAME);
    const [intakeOpen, setIntakeOpen] = useState(false);
    const [referenceState, setReferenceState] = useState<'idle' | 'cached' | 'running' | 'ready'>('cached');
    const [referenceProgress, setReferenceProgress] = useState(100);
    const [referenceStep, setReferenceStep] = useState('Cached evidence loaded');
    const [expandedBlock, setExpandedBlock] = useState<number | null>(null);
    const [selectedTrace, setSelectedTrace] = useState<ToolTrace>(TOOL_TRACES[1]);
    const [evalRunning, setEvalRunning] = useState(false);
    const [evalProgress, setEvalProgress] = useState(100);
    const [monitoringEnabled, setMonitoringEnabled] = useState(true);
    const [policyProfile, setPolicyProfile] = useState('Internal knowledge assistant');
    const [artifact, setArtifact] = useState<ArtifactAnalysis | null>(null);
    const [artifactProgress, setArtifactProgress] = useState<AnalysisProgress | null>(null);
    const [artifactError, setArtifactError] = useState<string | null>(null);
    const [sideCollapsed, setSideCollapsed] = useState(false);
    const fileInputRef = useRef<HTMLInputElement | null>(null);

    useEffect(() => {
        const stored = window.localStorage.getItem('vigil-monitoring-enabled');
        if (stored !== null) setMonitoringEnabled(stored === 'true');
    }, []);

    useEffect(() => {
        window.localStorage.setItem('vigil-monitoring-enabled', String(monitoringEnabled));
    }, [monitoringEnabled]);

    useEffect(() => {
        if (referenceState !== 'running') return;
        const steps = [
            [12, 'Resolving immutable model revision'],
            [28, 'Reading architecture and tensor manifests'],
            [49, 'Checking cached artifact roots'],
            [68, 'Scheduling static safety probes'],
            [84, 'Loading nearest behavioral baseline'],
            [100, 'Progressive analysis started'],
        ] as const;
        let stepIndex = 0;
        const interval = window.setInterval(() => {
            const [progress, label] = steps[stepIndex];
            setReferenceProgress(progress);
            setReferenceStep(label);
            stepIndex += 1;
            if (stepIndex >= steps.length) {
                window.clearInterval(interval);
                setReferenceState('ready');
            }
        }, 360);
        return () => window.clearInterval(interval);
    }, [referenceState]);

    useEffect(() => {
        if (!evalRunning) return;
        setEvalProgress(0);
        const interval = window.setInterval(() => {
            setEvalProgress(value => {
                const next = Math.min(100, value + 4);
                if (next === 100) {
                    window.clearInterval(interval);
                    setEvalRunning(false);
                }
                return next;
            });
        }, 180);
        return () => window.clearInterval(interval);
    }, [evalRunning]);

    const displayName = artifact?.fileName ?? modelName;

    const categories = useMemo(() => {
        if (!artifact || artifact.tensors.length === 0) return MODEL_CATEGORIES.map(category => ({ ...category }));
        const grouped = new Map<TensorCategory, { tensors: number; bytes: number }>();
        for (const tensor of artifact.tensors) {
            const current = grouped.get(tensor.category) ?? { tensors: 0, bytes: 0 };
            current.tensors += 1;
            current.bytes += tensor.bytes;
            grouped.set(tensor.category, current);
        }
        const largest = Math.max(...Array.from(grouped.values(), entry => entry.bytes), 1);
        return Array.from(grouped.entries())
            .sort((a, b) => b[1].bytes - a[1].bytes)
            .map(([id, entry]) => ({
                id,
                label: id.toUpperCase(),
                tensors: entry.tensors,
                bytes: formatBytes(entry.bytes),
                fraction: entry.bytes / largest,
                tone: categoryColor(id),
                detail: `${entry.tensors.toLocaleString()} indexed tensors mapped to verified on-disk byte ranges.`,
            }));
    }, [artifact]);

    const tensorCount = artifact?.tensorCount ?? 667;
    const architecture = artifact?.architecture ?? 'gemma4 · GGUF v3';
    const onDisk = artifact ? `1 file · ${formatBytes(artifact.fileSize)}` : '2 files · 7.15 GB';
    const analysisFreshness = artifact ? 'LOCAL · JUST NOW' : referenceState === 'cached' ? 'CACHE · 8 MIN OLD' : 'PROGRESSIVE · LIVE';

    function inspectReference() {
        const normalized = normalizeModelReference(modelReference);
        setModelName(normalized);
        setArtifact(null);
        setArtifactError(null);
        const cacheHit = /gemma-4-12b-qat|qwen3-8b|llama-3\.1-8b/i.test(normalized);
        if (cacheHit) {
            setReferenceState('cached');
            setReferenceProgress(100);
            setReferenceStep('Content-addressed analysis cache hit');
        } else {
            setReferenceState('running');
            setReferenceProgress(4);
            setReferenceStep('Resolving model reference');
        }
    }

    async function handleArtifactFile(event: ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) return;
        setArtifact(null);
        setArtifactError(null);
        setArtifactProgress({ stage: 'metadata', fraction: 0, message: 'Opening local artifact' });
        setIntakeOpen(false);
        setActiveTab('integrity');
        setModelName(file.name);
        setReferenceState('running');
        try {
            const result = await analyzeLocalArtifact(file, setArtifactProgress);
            setArtifact(result);
            setReferenceState('ready');
            setReferenceStep('Local artifact indexed and Merkle-rooted');
            setArtifactProgress(null);
        } catch (error) {
            setArtifactError(error instanceof Error ? error.message : 'The artifact could not be analyzed.');
            setReferenceState('ready');
            setArtifactProgress(null);
        }
    }

    function exportReport() {
        const report = {
            schema: 'vigil.decision-report.v1',
            generatedAt: new Date().toISOString(),
            model: displayName,
            profile: policyProfile,
            decision: 'approve-with-controls',
            evidenceMode: artifact ? 'local-artifact' : 'simulated-demo',
            artifact: artifact ? {
                format: artifact.format,
                architecture: artifact.architecture,
                size: artifact.fileSize,
                tensorCount: artifact.tensorCount,
                merkleRoot: artifact.merkleRoot,
            } : null,
            controls: [
                'Read-only tools by default',
                'Human approval for external, destructive, or financial actions',
                'Prompt-injection and taint checks before tool execution',
                'Event-triggered re-evaluation on any artifact, runtime, tool, or policy change',
            ],
            limitations: [
                'Cryptographic integrity does not establish behavioral safety.',
                'No backdoor detector proves the absence of hidden behavior.',
                'Behavioral evidence in this prototype is simulated.',
            ],
        };
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `vigil-${displayName.replace(/[^a-z0-9]+/gi, '-')}-report.json`;
        anchor.click();
        URL.revokeObjectURL(url);
    }

    function renderVisualize() {
        return <div className={s.stack} data-testid="visualize-view">
            <div className={s.twoColumn}>
                <section className={s.card}>
                    <div className={s.cardHeading}>
                        <h2>Model identity</h2>
                        <span className={s.monoLabel}>{artifact ? `${artifact.format.toUpperCase()} · LOCAL` : 'GGUF · RESOLVED'}</span>
                    </div>
                    <dl className={s.identityGrid}>
                        <div><dt>Architecture</dt><dd>{architecture}</dd></div>
                        <div><dt>Layers</dt><dd>{artifact ? inferLayerCount(artifact) : 48}</dd></div>
                        <div><dt>Tensors</dt><dd>{tensorCount.toLocaleString()}</dd></div>
                        <div><dt>Quantization</dt><dd className={s.tags}>{artifact ? <span>{inferQuantization(artifact)}</span> : <><span>F32×338</span><span>Q6_K×1</span><span>Q4_0×328</span></>}</dd></div>
                        <div><dt>On disk</dt><dd>{onDisk}</dd></div>
                        <div><dt>Evidence</dt><dd>{artifact ? 'Local bytes · no upload' : 'Repository revision + cached run'}</dd></div>
                    </dl>
                </section>

                <section className={s.card}>
                    <div className={s.cardHeading}>
                        <h2>Weights by category</h2>
                        <span className={s.monoLabel}>INDEXED SURFACE</span>
                    </div>
                    <div className={s.categoryList}>
                        {categories.map(category => <div className={s.category} key={category.id}>
                            <div className={s.categoryTop}>
                                <div><i className={clsx(s.categoryDot, s[`tone_${category.tone}`])} />{category.label} · {category.tensors} tensors</div>
                                <span>{category.bytes}</span>
                            </div>
                            <div className={s.barTrack}><div className={clsx(s.barFill, s[`tone_${category.tone}`])} style={{ width: `${Math.max(1, category.fraction * 100)}%` }} /></div>
                            <p>{category.detail}</p>
                        </div>)}
                    </div>
                </section>
            </div>

            <section className={clsx(s.card, s.modelMapCard)}>
                <div className={s.mapHeader}>
                    <div>
                        <div className={s.cardHeadingInline}>
                            <h2>Model map</h2>
                            <span className={s.monoLabel}>{artifact ? 'REAL LOCAL INDEX' : 'ARCHITECTURE-FAITHFUL SIMULATION'} · {tensorCount.toLocaleString()} TENSORS</span>
                        </div>
                        <p>{mapMode === '3d'
                            ? 'Interactive transformer topology. Rotate, zoom, and inspect the inherited LLM visualization.'
                            : 'Rows are sized by bytes. Expand a block for its tensors; integrity mode maps byte ranges to Merkle leaves.'}</p>
                    </div>
                    <div className={s.segmented} aria-label="Model map mode">
                        {(['3d', 'category', 'integrity', 'diff'] as MapMode[]).map(mode => <button
                            key={mode}
                            className={clsx(mapMode === mode && s.segmentActive)}
                            onClick={() => setMapMode(mode)}
                            aria-pressed={mapMode === mode}
                        >{mode === '3d' ? '3D topology' : mode}</button>)}
                    </div>
                </div>

                {mapMode === '3d' ? <div className={s.visualizerFrame}>
                    <iframe title="Interactive 3D transformer model" src="/vigil/model-map" />
                    <div className={s.frameCaption}>
                        <span><FontAwesomeIcon icon={faCube} /> Renderer inherited from bbycroft/llm-viz</span>
                        <span>Visualization is assumed until a compatible runtime graph is loaded</span>
                    </div>
                </div> : <div className={s.modelRows}>
                    <button className={clsx(s.modelRow, s.embeddingRow)} onClick={() => setExpandedBlock(expandedBlock === -1 ? null : -1)}>
                        <span><FontAwesomeIcon icon={expandedBlock === -1 ? faChevronDown : faChevronRight} /> token_embd.weight · {artifact ? matchingCount(artifact, 'embedding') : 1} tensor</span>
                        <span>{artifact ? categoryBytes(artifact, 'embedding') : '825.8 MB'}</span>
                    </button>
                    {expandedBlock === -1 && <TensorDetails artifact={artifact} category="embedding" />}
                    {TRANSFORMER_BLOCKS.map(block => <React.Fragment key={block.id}>
                        <button
                            className={clsx(s.modelRow, mapMode === 'integrity' && block.integrity === 'review' && s.rowReview)}
                            onClick={() => setExpandedBlock(expandedBlock === block.id ? null : block.id)}
                        >
                            <span><FontAwesomeIcon icon={expandedBlock === block.id ? faChevronDown : faChevronRight} /> blk.{block.id} · {block.tensors} tensors</span>
                            <span>{block.bytes}</span>
                            <i className={clsx(
                                s.rowSignal,
                                mapMode === 'diff' ? s.diffSignal : mapMode === 'integrity' ? s.integritySignal : s.categorySignal,
                            )} style={{ width: mapMode === 'diff' ? `${Math.min(100, block.delta * 26)}%` : undefined }} />
                        </button>
                        {expandedBlock === block.id && <TensorDetails artifact={artifact} block={block.id} />}
                    </React.Fragment>)}
                </div>}
            </section>
        </div>;
    }

    function renderStatic() {
        const complete = STATIC_CHECKS.filter(check => check.status === 'pass' || check.status === 'verified').length;
        return <div className={s.stack} data-testid="static-view">
            <div className={s.metricGrid}>
                <MetricCard label="Structural checks" value={`${complete}/${STATIC_CHECKS.length}`} detail="One research signal remains unknown" tone="green" />
                <MetricCard label="Executable payloads" value="0" detail="Parsed without loading model code" tone="blue" />
                <MetricCard label="Parent delta" value="2.7%" detail="Expected for declared QAT lineage" tone="blue" />
                <MetricCard label="Review surfaces" value="2" detail="Layers 31 and 42 need probes" tone="amber" />
            </div>

            <div className={s.twoColumnWide}>
                <section className={s.card}>
                    <div className={s.cardHeading}>
                        <div><h2>Static integrity checks</h2><p>Deterministic checks first; experimental detectors stay visibly qualified.</p></div>
                        <StatusPill status="finding">1 finding</StatusPill>
                    </div>
                    <div className={s.checkList}>
                        {STATIC_CHECKS.map(check => <article className={s.checkRow} key={check.id}>
                            <StatusPill status={check.status} />
                            <div>
                                <h3>{check.title}</h3>
                                <p>{check.detail}</p>
                                <small>{check.evidence}</small>
                            </div>
                            <span className={clsx(s.risk, s[`risk_${check.risk}`])}>{check.risk}</span>
                        </article>)}
                    </div>
                </section>

                <div className={s.stackSmall}>
                    <section className={s.card}>
                        <div className={s.cardHeading}>
                            <div><h2>Weight-delta fingerprint</h2><p>Per-layer deviation from the declared parent.</p></div>
                            <span className={s.monoLabel}>WHITE-BOX</span>
                        </div>
                        <div className={s.deltaChart} aria-label="Layer weight delta chart">
                            {TRANSFORMER_BLOCKS.map(block => <div key={block.id} title={`Layer ${block.id}: ${block.delta.toFixed(1)}σ`}>
                                <i className={clsx(block.delta >= 2 ? s.deltaHigh : block.delta >= 1.2 ? s.deltaMedium : s.deltaNormal)} style={{ height: `${12 + block.delta * 28}px` }} />
                            </div>)}
                        </div>
                        <div className={s.chartAxis}><span>blk.0</span><span>blk.24</span><span>blk.47</span></div>
                        <div className={s.calloutAmber}>
                            <FontAwesomeIcon icon={faTriangleExclamation} />
                            <p><strong>An anomaly is not a backdoor.</strong> Weight-space signals prioritize deeper tests; they do not establish intent.</p>
                        </div>
                    </section>

                    <section className={s.card}>
                        <div className={s.cardHeading}><h2>Backdoor research signals</h2><span className={s.monoLabel}>EXPERIMENTAL</span></div>
                        <div className={s.signalRows}>
                            <SignalRow label="Attention hijack pattern" value="No candidate" status="pass" />
                            <SignalRow label="Output entropy collapse" value="Scanning" status="running" />
                            <SignalRow label="Memorized trigger motifs" value="Not run" status="not-run" />
                            <SignalRow label="Activation defection probe" value="Queued" status="unknown" />
                        </div>
                    </section>
                </div>
            </div>
        </div>;
    }

    function renderDynamic() {
        return <div className={s.stack} data-testid="dynamic-view">
            <section className={s.card}>
                <div className={s.runHeader}>
                    <div>
                        <span className={s.eyebrow}>BEHAVIORAL EVIDENCE</span>
                        <h2>Dynamic evaluation suite</h2>
                        <p>Use-case tests, adversarial probes, and repeatable baselines. Demo results are simulated in this frontend.</p>
                    </div>
                    <button className={s.primaryButton} onClick={() => setEvalRunning(true)} disabled={evalRunning}>
                        <FontAwesomeIcon icon={evalRunning ? faRotate : faPlay} spin={evalRunning} />
                        {evalRunning ? 'Evaluation running' : 'Run full evaluation'}
                    </button>
                </div>
                <div className={s.progressLine}><i style={{ width: `${evalProgress}%` }} /></div>
                <div className={s.progressMeta}><span>{evalProgress}% · {evalRunning ? 'Executing isolated scenarios' : '2,148 scenarios completed'}</span><span>Baseline: 2026-07-21</span></div>
            </section>

            <div className={s.suiteGrid}>
                {DYNAMIC_SUITES.map(suite => <article className={s.card} key={suite.label}>
                    <div className={s.suiteTop}><span>{suite.label}</span><StatusPill status={suite.status === 'finding' ? 'finding' : 'pass'} /></div>
                    <div className={s.scoreLine}><strong>{suite.score}</strong><span>/100</span><em className={suite.delta.startsWith('-') ? s.deltaNegative : s.deltaPositive}>{suite.delta}</em></div>
                    <div className={s.barTrack}><div className={clsx(s.barFill, suite.status === 'finding' ? s.tone_amber : s.tone_teal)} style={{ width: `${suite.score}%` }} /></div>
                    <small>{suite.tests} passed</small>
                </article>)}
            </div>

            <section className={s.card}>
                <div className={s.cardHeading}>
                    <div><h2>Recent adversarial cases</h2><p>Every score links back to the prompt, runtime, grader, and raw evidence.</p></div>
                    <button className={s.secondaryButton}><FontAwesomeIcon icon={faMagnifyingGlass} /> Explore all traces</button>
                </div>
                <div className={s.tableWrap}>
                    <table className={s.dataTable}>
                        <thead><tr><th>Case</th><th>Suite</th><th>Result</th><th>Severity</th><th>Evidence</th></tr></thead>
                        <tbody>{EVALUATION_CASES.map(item => <tr key={item.id}>
                            <td className={s.mono}>{item.id}</td>
                            <td>{item.suite}</td>
                            <td><StatusPill status={item.result === 'finding' || item.result === 'blocked' ? 'finding' : 'pass'}>{item.result}</StatusPill></td>
                            <td><span className={clsx(s.risk, s[`risk_${item.severity}`])}>{item.severity}</span></td>
                            <td>{item.evidence}</td>
                        </tr>)}</tbody>
                    </table>
                </div>
            </section>
        </div>;
    }

    function renderTools() {
        return <div className={s.stack} data-testid="tools-view">
            <div className={s.metricGrid}>
                <MetricCard label="Calls evaluated" value="18,442" detail="Across 30-day baseline" tone="blue" />
                <MetricCard label="Unsafe calls blocked" value="83" detail="0 reached execution" tone="green" />
                <MetricCard label="Approval gates" value="217" detail="96.8% approved by humans" tone="amber" />
                <MetricCard label="Tool contract drift" value="0" detail="Schemas pinned and verified" tone="green" />
            </div>

            <div className={s.traceLayout}>
                <section className={s.card}>
                    <div className={s.cardHeading}>
                        <div><h2>Tool-call integrity trace</h2><p>Selection, arguments, taint, policy, side effect, and observed impact.</p></div>
                        <span className={s.liveDot}>LIVE BASELINE</span>
                    </div>
                    <div className={s.traceList}>
                        {TOOL_TRACES.map(trace => <button
                            key={trace.id}
                            className={clsx(s.traceRow, selectedTrace.id === trace.id && s.traceSelected)}
                            onClick={() => setSelectedTrace(trace)}
                        >
                            <span className={s.mono}>{trace.time}</span>
                            <div><strong>{trace.tool}</strong><small>{trace.action}</small></div>
                            <StatusPill status={trace.decision === 'allowed' ? 'pass' : trace.decision === 'blocked' ? 'blocked' : 'approval'}>{trace.decision}</StatusPill>
                            <FontAwesomeIcon icon={faChevronRight} />
                        </button>)}
                    </div>
                </section>

                <section className={s.card}>
                    <div className={s.cardHeading}>
                        <h2>Trace {selectedTrace.id}</h2>
                        <StatusPill status={selectedTrace.decision === 'allowed' ? 'pass' : selectedTrace.decision === 'blocked' ? 'blocked' : 'approval'}>{selectedTrace.decision}</StatusPill>
                    </div>
                    <div className={s.traceFlow}>
                        <TraceNode icon={faTerminal} label="Intent" value="Resolve one customer support request" />
                        <TraceNode icon={faWrench} label="Tool" value={selectedTrace.tool} />
                        <TraceNode icon={faSliders} label="Arguments" value={selectedTrace.target} />
                        <TraceNode icon={faShieldHalved} label="Policy decision" value={selectedTrace.reason} />
                    </div>
                    <div className={s.detailGrid}>
                        <div><span>Data taint</span><strong>{selectedTrace.taint.join(' · ')}</strong></div>
                        <div><span>Credentials</span><strong>Ephemeral · task-bound</strong></div>
                        <div><span>Side effect</span><strong>{selectedTrace.decision === 'allowed' ? 'Read only' : 'Never executed'}</strong></div>
                        <div><span>Outcome</span><strong>{selectedTrace.impact}</strong></div>
                    </div>
                    <div className={selectedTrace.decision === 'blocked' ? s.calloutRed : s.calloutGreen}>
                        <FontAwesomeIcon icon={selectedTrace.decision === 'blocked' ? faLock : faCheck} />
                        <p>{selectedTrace.impact}</p>
                    </div>
                </section>
            </div>

            <section className={s.card}>
                <div className={s.cardHeading}><div><h2>Outcome ledger</h2><p>Judge the model by realized utility and harm—not just refusal rates.</p></div><span className={s.monoLabel}>30 DAYS</span></div>
                <div className={s.outcomeGrid}>
                    <Outcome label="Useful outcomes" value="14,893" detail="Grounded answers or completed safe tasks" tone="green" />
                    <Outcome label="Prevented harms" value="83" detail="Exfiltration, destructive actions, or unsafe pivots" tone="blue" />
                    <Outcome label="Human-corrected" value="41" detail="Material answer or action changed before delivery" tone="amber" />
                    <Outcome label="Confirmed harm" value="0" detail="No verified production impact in this baseline" tone="slate" />
                </div>
            </section>
        </div>;
    }

    function renderIntegrity() {
        const root = artifact?.merkleRoot ?? MERKLE_SAMPLE.root;
        return <div className={s.stack} data-testid="integrity-view">
            <section className={s.card}>
                <div className={s.runHeader}>
                    <div>
                        <span className={s.eyebrow}>CONTENT-ADDRESSED EVIDENCE</span>
                        <h2>Artifact integrity and Merkle index</h2>
                        <p>Verify a local GGUF or Safetensors file in this browser. Model bytes are not uploaded.</p>
                    </div>
                    <button className={s.primaryButton} onClick={() => fileInputRef.current?.click()}>
                        <FontAwesomeIcon icon={faUpload} /> Verify local artifact
                    </button>
                </div>
                {artifactProgress && <div className={s.localProgress}>
                    <div className={s.progressLine}><i style={{ width: `${Math.max(2, artifactProgress.fraction * 100)}%` }} /></div>
                    <span>{artifactProgress.message}</span>
                </div>}
                {artifactError && <div className={s.calloutRed}><FontAwesomeIcon icon={faCircleExclamation} /><p>{artifactError}</p></div>}
                {artifact && <div className={s.calloutGreen}>
                    <FontAwesomeIcon icon={faCheck} />
                    <p><strong>{artifact.fileName}</strong> indexed: {artifact.tensorCount.toLocaleString()} tensors, {artifact.leaves.length.toLocaleString()} chunks, root {formatHash(artifact.merkleRoot)}.</p>
                </div>}
            </section>

            <div className={s.twoColumnWide}>
                <section className={s.card}>
                    <div className={s.cardHeading}>
                        <div><h2>Merkle proof tree</h2><p>Domain-separated SHA-256 leaves bind file name, size, chunk index, offset, length, and bytes.</p></div>
                        <StatusPill status={artifact ? 'verified' : 'cached'}>{artifact ? 'local proof' : 'cached proof'}</StatusPill>
                    </div>
                    <div className={s.merkleTree}>
                        <div className={s.rootNode}>
                            <FontAwesomeIcon icon={faFingerprint} />
                            <div><span>MODEL ROOT</span><code>{formatHash(root, 20, 18)}</code></div>
                        </div>
                        <div className={s.treeLevel}>
                            {(artifact ? [{
                                name: artifact.fileName,
                                root: artifact.merkleRoot,
                                leaves: artifact.leaves.length,
                                state: 'verified',
                            }] : MERKLE_SAMPLE.files).map(file => <div className={s.fileNode} key={file.name}>
                                <div className={s.fileNodeTop}><FontAwesomeIcon icon={faFileShield} /><div><strong>{file.name}</strong><code>{formatHash(file.root)}</code></div><StatusPill status="verified" /></div>
                                <div className={s.leafGrid}>
                                    {(artifact ? artifact.leaves.slice(0, 8) : Array.from({ length: 8 }, (_, index) => ({ index, hash: `${(index + 31).toString(16)}0c9a2f…${(index + 82).toString(16)}d41` }))).map(leaf => <div key={leaf.index}>
                                        <span>L{leaf.index.toString().padStart(4, '0')}</span>
                                        <code>{formatHash(leaf.hash, 7, 5)}</code>
                                    </div>)}
                                    {file.leaves > 8 && <button onClick={() => setMapMode('integrity')}><span>+{(file.leaves - 8).toLocaleString()}</span><small>more leaves</small></button>}
                                </div>
                            </div>)}
                        </div>
                    </div>
                </section>

                <div className={s.stackSmall}>
                    <section className={s.card}>
                        <div className={s.cardHeading}><h2>What this proves</h2><FontAwesomeIcon icon={faLock} /></div>
                        <ul className={s.proofList}>
                            <li><FontAwesomeIcon icon={faCheck} /><span><strong>Sameness</strong> — the verified bytes match this exact root.</span></li>
                            <li><FontAwesomeIcon icon={faCheck} /><span><strong>Localization</strong> — a changed chunk maps back to affected tensor ranges.</span></li>
                            <li><FontAwesomeIcon icon={faCheck} /><span><strong>Efficient re-checks</strong> — unchanged leaves can be reused from cache.</span></li>
                            <li className={s.proofDoesNot}><FontAwesomeIcon icon={faXmark} /><span><strong>Not benevolence</strong> — matching bytes can still encode unsafe behavior.</span></li>
                        </ul>
                    </section>
                    <section className={s.card}>
                        <div className={s.cardHeading}><h2>Supply-chain attestation</h2><span className={s.monoLabel}>POLICY</span></div>
                        <div className={s.signalRows}>
                            <SignalRow label="Immutable revision" value="Verified" status="verified" />
                            <SignalRow label="Publisher signature" value="Not supplied" status="unknown" />
                            <SignalRow label="ML-BOM pedigree" value="Partial" status="finding" />
                            <SignalRow label="Evaluation attestation" value="Bound to root" status="verified" />
                        </div>
                    </section>
                    {artifact && <section className={s.card}>
                        <div className={s.cardHeading}><h2>Local tensor index</h2><span className={s.monoLabel}>{artifact.format}</span></div>
                        <div className={s.tensorIndexPreview}>
                            {artifact.tensors.slice(0, 7).map(tensor => <div key={tensor.name}>
                                <strong>{tensor.name}</strong>
                                <span>{tensor.dtype} · [{tensor.shape.join(' × ')}] · {formatBytes(tensor.bytes)}</span>
                                <small>Merkle leaves {tensor.chunkStart}–{tensor.chunkEnd}</small>
                            </div>)}
                        </div>
                    </section>}
                </div>
            </div>
        </div>;
    }

    function renderMonitor() {
        return <div className={s.stack} data-testid="monitor-view">
            <section className={s.card}>
                <div className={s.monitorHeader}>
                    <div className={s.monitorState}>
                        <span className={clsx(s.monitorOrb, monitoringEnabled && s.monitorOrbActive)}><FontAwesomeIcon icon={monitoringEnabled ? faBolt : faPause} /></span>
                        <div><span className={s.eyebrow}>CONTINUOUS ASSURANCE</span><h2>{monitoringEnabled ? 'Monitoring active' : 'Monitoring paused'}</h2><p>Event-triggered checks plus scheduled behavioral canaries.</p></div>
                    </div>
                    <button className={clsx(s.toggle, monitoringEnabled && s.toggleOn)} onClick={() => setMonitoringEnabled(value => !value)} aria-pressed={monitoringEnabled}>
                        <i /><span>{monitoringEnabled ? 'Active' : 'Paused'}</span>
                    </button>
                </div>
            </section>

            <div className={s.monitorGrid}>
                <section className={s.card}>
                    <div className={s.cardHeading}><div><h2>Trigger matrix</h2><p>Any material input change invalidates the affected evidence.</p></div><span className={s.monoLabel}>EVENT DRIVEN</span></div>
                    <div className={s.triggerList}>
                        <MonitorTrigger icon={faFingerprint} title="Artifact root changes" detail="Quarantine immediately; re-run static and full dynamic suite." state="armed" />
                        <MonitorTrigger icon={faCodeBranch} title="Runtime or quantization changes" detail="Re-hash runtime bundle and run numeric parity + behavior canaries." state="armed" />
                        <MonitorTrigger icon={faWrench} title="Tool schema or permission changes" detail="Re-baseline tool selection, arguments, scopes, and side effects." state="armed" />
                        <MonitorTrigger icon={faSliders} title="System prompt or policy changes" detail="Invalidate agentic verdict; rerun goal, injection, and approval tests." state="armed" />
                        <MonitorTrigger icon={faDatabase} title="RAG corpus changes" detail="Re-test indirect injection, data boundary, and grounding controls." state="armed" />
                    </div>
                </section>

                <div className={s.stackSmall}>
                    <section className={s.card}>
                        <div className={s.cardHeading}><h2>Scheduled loop</h2><FontAwesomeIcon icon={faClockRotateLeft} /></div>
                        <div className={s.scheduleList}>
                            <div><span>Every inference</span><strong>Root + runtime identity gate</strong><StatusPill status="verified" /></div>
                            <div><span>Hourly</span><strong>Golden canaries + tool contracts</strong><StatusPill status="pass" /></div>
                            <div><span>Daily</span><strong>Production outcome drift</strong><StatusPill status="pass" /></div>
                            <div><span>Weekly</span><strong>Adversarial regression pack</strong><StatusPill status="finding">1 finding</StatusPill></div>
                            <div><span>Quarterly</span><strong>Independent human red team</strong><StatusPill status="not-run">Due Sep 30</StatusPill></div>
                        </div>
                    </section>
                    <section className={s.card}>
                        <div className={s.cardHeading}><h2>Drift now</h2><span className={s.monoLabel}>VS BASELINE</span></div>
                        <div className={s.driftGrid}>
                            <div><span>Artifact</span><strong>0 changed leaves</strong><em>stable</em></div>
                            <div><span>Behavior</span><strong>1.4% max delta</strong><em>within band</em></div>
                            <div><span>Tools</span><strong>0 schema changes</strong><em>stable</em></div>
                            <div><span>Outcomes</span><strong>+0.7% utility</strong><em>improving</em></div>
                        </div>
                    </section>
                </div>
            </div>

            <section className={s.card}>
                <div className={s.cardHeading}><div><h2>Integrity timeline</h2><p>Append-only evidence events bound to model and policy roots.</p></div><button className={s.secondaryButton}><FontAwesomeIcon icon={faDownload} /> Export log</button></div>
                <div className={s.timeline}>
                    <TimelineEvent time="14:32 today" title="Dynamic canaries completed" detail="200/200 core cases passed; jailbreak pack retained one moderate finding." tone="green" />
                    <TimelineEvent time="12:00 today" title="Hourly identity gate" detail="Artifact, runtime, prompt, tool, and policy roots match approved baseline." tone="blue" />
                    <TimelineEvent time="Jul 22" title="Tool baseline approved" detail="billing.refund moved behind human approval after impact review." tone="amber" />
                    <TimelineEvent time="Jul 21" title="Model admitted to pilot" detail="Decision: approve with controls for Internal Knowledge Assistant." tone="green" />
                </div>
            </section>
        </div>;
    }

    function renderDecision() {
        const policyDecision = policyProfile === 'Autonomous operations' ? 'Pilot only' : 'Approve with controls';
        return <div className={s.stack} data-testid="decision-view">
            <section className={clsx(s.card, s.decisionHero)}>
                <div className={s.decisionMark}><FontAwesomeIcon icon={policyProfile === 'Autonomous operations' ? faTriangleExclamation : faShieldHalved} /></div>
                <div className={s.decisionCopy}>
                    <span className={s.eyebrow}>USE-CASE DECISION</span>
                    <h2>{policyDecision}</h2>
                    <p>For <strong>{policyProfile}</strong>, current evidence supports a constrained deployment—not unrestricted trust.</p>
                    <div className={s.decisionBadges}><StatusPill status="verified">artifact verified</StatusPill><StatusPill status="pass">behavior acceptable</StatusPill><StatusPill status="finding">controls required</StatusPill></div>
                </div>
                <div className={s.profileControl}>
                    <label htmlFor="policy-profile">Decision profile</label>
                    <select id="policy-profile" value={policyProfile} onChange={event => setPolicyProfile(event.target.value)}>
                        <option>Internal knowledge assistant</option>
                        <option>Customer support copilot</option>
                        <option>Software engineering agent</option>
                        <option>Autonomous operations</option>
                    </select>
                    <small>Verdicts change when authority, data, users, or impact change.</small>
                </div>
            </section>

            <div className={s.decisionColumns}>
                <section className={s.card}>
                    <div className={s.cardHeading}><h2>Trust planes</h2><span className={s.monoLabel}>SEPARATE VERDICTS</span></div>
                    <div className={s.trustPlanes}>
                        <TrustPlane label="Artifact & supply chain" score="91" status="verified" detail="Bytes rooted; publisher signature and full training pedigree missing." />
                        <TrustPlane label="Model behavior" score="84" status="pass" detail="Strong task fitness; jailbreak and cyber misuse findings remain." />
                        <TrustPlane label="Agent & tool controls" score="88" status="finding" detail="Safe with least-agency policy and approval gates enforced." />
                        <TrustPlane label="Operational assurance" score="96" status="verified" detail="Event triggers, rollback, evidence logs, and canaries configured." />
                    </div>
                </section>

                <section className={s.card}>
                    <div className={s.cardHeading}><h2>Evidence confidence</h2><span className={s.monoLabel}>NOT A SAFETY SCORE</span></div>
                    <div className={s.confidenceRing}><strong>87%</strong><span>coverage</span></div>
                    <ul className={s.coverageList}>
                        <li><span>Deterministic artifact evidence</span><strong>100%</strong></li>
                        <li><span>Use-case behavioral coverage</span><strong>92%</strong></li>
                        <li><span>Backdoor research coverage</span><strong>61%</strong></li>
                        <li><span>Independent assessment</span><strong>0%</strong></li>
                    </ul>
                    <div className={s.calloutAmber}><FontAwesomeIcon icon={faCircleInfo} /><p>Unknown evidence reduces confidence; it never silently converts to a pass.</p></div>
                </section>
            </div>

            <div className={s.threeColumn}>
                <DecisionList tone="green" title="Approved uses" items={[
                    'Internal retrieval and summarization',
                    'Drafting with human review',
                    'Read-only support lookups',
                    'Sandboxed coding assistance',
                ]} />
                <DecisionList tone="amber" title="Required controls" items={[
                    'Pin artifact and runtime roots',
                    'Read-only tools by default',
                    'Human approval for material side effects',
                    'Continuous trace and outcome monitoring',
                ]} />
                <DecisionList tone="red" title="Not approved" items={[
                    'Unreviewed external communications',
                    'Autonomous financial actions',
                    'Direct access to regulated records',
                    'Safety-critical final decisions',
                ]} />
            </div>

            <section className={s.card}>
                <div className={s.reportFooter}>
                    <div><h2>Decision package</h2><p>Export a machine-readable record of the verdict, controls, evidence mode, root, and limitations.</p></div>
                    <button className={s.primaryButton} onClick={exportReport}><FontAwesomeIcon icon={faDownload} /> Export decision JSON</button>
                </div>
            </section>
        </div>;
    }

    const content = activeTab === 'visualize' ? renderVisualize()
        : activeTab === 'static' ? renderStatic()
            : activeTab === 'dynamic' ? renderDynamic()
                : activeTab === 'tools' ? renderTools()
                    : activeTab === 'integrity' ? renderIntegrity()
                        : activeTab === 'monitor' ? renderMonitor()
                            : renderDecision();

    return <main className={s.console}>
        <input ref={fileInputRef} className={s.hiddenInput} type="file" accept=".gguf,.safetensors" onChange={handleArtifactFile} />
        <aside className={clsx(s.sidebar, sideCollapsed && s.sidebarCollapsed)}>
            <div className={s.brand}>
                <div><strong>VIGIL</strong><span>MODEL TRUST CONSOLE</span></div>
                <button className={s.collapseButton} onClick={() => setSideCollapsed(value => !value)} aria-label={sideCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
                    <FontAwesomeIcon icon={sideCollapsed ? faArrowRight : faArrowLeft} />
                </button>
            </div>
            <button className={s.allModels} onClick={() => setIntakeOpen(true)}><FontAwesomeIcon icon={faMagnifyingGlass} /><span>Inspect model</span></button>
            <div className={s.sideSection}>
                <span className={s.sideLabel}>MODELS</span>
                <button className={s.modelNav} onClick={() => setActiveTab('visualize')}>
                    <i /><span>{displayName}</span>
                </button>
            </div>
            <div className={s.sideSection}>
                <span className={s.sideLabel}>WORKBENCH</span>
                <nav className={s.sideNav}>
                    {SIDE_LINKS.map(link => <button key={link.id} className={clsx(activeTab === link.id && s.sideNavActive)} onClick={() => setActiveTab(link.id)}>
                        <small>{link.code}</small><span>{link.label}</span>
                    </button>)}
                </nav>
            </div>
            <div className={s.sideSection}>
                <span className={s.sideLabel}>FLEETS</span>
                <div className={s.fleet}><i className={s.fleetOnline} /><span>Prod Assistant (US)</span></div>
                <div className={s.fleet}><i /><span>EU Copilot (data-resident)</span></div>
            </div>
            <div className={s.sidebarBottom}>
                <div><FontAwesomeIcon icon={faLock} /><span>LOCAL-FIRST ANALYSIS</span></div>
                <small>TRIPNINE · SUPERADMIN</small>
                <small>MODE PRODUCTION · EVIDENCE DEMO</small>
            </div>
        </aside>

        <div className={s.workspace}>
            <header className={s.topbar}>
                <div className={s.titleArea}>
                    <span className={s.breadcrumb}>MODEL · {artifact ? 'LOCAL ARTIFACT' : 'HUGGING FACE'} · {analysisFreshness}</span>
                    <h1>{displayName}</h1>
                    <div className={s.badgeRow}>
                        <EvidenceBadge tone="green">ARTIFACT ROOTED</EvidenceBadge>
                        <EvidenceBadge tone="green">TENSORS INDEXED</EvidenceBadge>
                        <EvidenceBadge tone="blue">TOOLS BASELINED</EvidenceBadge>
                        <EvidenceBadge tone="amber">1 FINDING</EvidenceBadge>
                        <EvidenceBadge tone="slate">EVIDENCE 87%</EvidenceBadge>
                    </div>
                </div>
                <div className={s.topActions}>
                    <div className={s.verdictMini}><span>DECISION</span><strong>APPROVE WITH CONTROLS</strong></div>
                    <button className={s.iconButton} aria-label="Notifications"><FontAwesomeIcon icon={faBell} /><i /></button>
                    <button className={s.secondaryButton} onClick={() => setIntakeOpen(true)}><FontAwesomeIcon icon={faLink} /> Inspect another</button>
                </div>
            </header>

            <nav className={s.tabBar} aria-label="Model analysis views">
                {TABS.map(tab => <button key={tab.id} className={clsx(activeTab === tab.id && s.tabActive)} onClick={() => setActiveTab(tab.id)}>
                    <FontAwesomeIcon icon={tab.icon} /><span>{tab.label}</span>
                </button>)}
            </nav>

            <div className={s.content}>{content}</div>
        </div>

        {intakeOpen && <div className={s.modalBackdrop} role="presentation" onMouseDown={event => event.target === event.currentTarget && setIntakeOpen(false)}>
            <section className={s.intakeModal} role="dialog" aria-modal="true" aria-labelledby="intake-title">
                <div className={s.modalHeader}>
                    <div><span className={s.eyebrow}>MODEL INTAKE</span><h2 id="intake-title">Inspect an open-weight model</h2><p>Paste a model reference for instant cached results or progressive analysis.</p></div>
                    <button onClick={() => setIntakeOpen(false)} aria-label="Close model intake"><FontAwesomeIcon icon={faXmark} /></button>
                </div>

                <label className={s.modelInputLabel} htmlFor="model-reference">Model URL, repository ID, Ollama tag, or OCI digest</label>
                <div className={s.modelInputRow}>
                    <FontAwesomeIcon icon={faLink} />
                    <input id="model-reference" value={modelReference} onChange={event => setModelReference(event.target.value)} placeholder="e.g. Qwen/Qwen3-8B or a Hugging Face URL" />
                    <button className={s.primaryButton} onClick={inspectReference}><FontAwesomeIcon icon={faBolt} /> Inspect</button>
                </div>
                <div className={s.exampleRow}>
                    <span>Try:</span>
                    {['Qwen/Qwen3-8B', 'meta-llama/Llama-3.1-8B-Instruct', 'unsloth/custom-lora'].map(example => <button key={example} onClick={() => setModelReference(example)}>{example}</button>)}
                </div>

                <div className={s.intakeDivider}><span>or verify bytes locally</span></div>
                <button className={s.uploadZone} onClick={() => fileInputRef.current?.click()}>
                    <FontAwesomeIcon icon={faUpload} />
                    <div><strong>Choose a GGUF or Safetensors file</strong><span>Metadata parsing, tensor indexing, and Merkle hashing happen in this browser.</span></div>
                    <FontAwesomeIcon icon={faChevronRight} />
                </button>

                <div className={s.intakeStatus}>
                    <div className={s.intakeStatusTop}>
                        <StatusPill status={referenceState === 'cached' ? 'cached' : referenceState === 'running' ? 'running' : 'verified'}>
                            {referenceState === 'cached' ? 'cache hit' : referenceState === 'running' ? 'analyzing' : 'ready'}
                        </StatusPill>
                        <span>{referenceStep}</span>
                        <strong>{referenceProgress}%</strong>
                    </div>
                    <div className={s.progressLine}><i style={{ width: `${referenceProgress}%` }} /></div>
                    <p>{referenceState === 'cached'
                        ? 'The cache is keyed by artifact root, runtime, evaluation suite, tool contracts, and policy—not by model name alone.'
                        : 'Metadata appears first. Cryptographic, static, and dynamic evidence fills in progressively as each stage completes.'}</p>
                </div>

                <div className={s.modalFootnote}><FontAwesomeIcon icon={faCircleInfo} /><span>A model reference may cause the future worker to fetch public model artifacts. Local-file verification never uploads the selected bytes.</span></div>
            </section>
        </div>}
    </main>;
}

function TensorDetails({ artifact, block, category }: { artifact: ArtifactAnalysis | null; block?: number; category?: TensorCategory }) {
    const matches = artifact?.tensors.filter(tensor => {
        if (category) return tensor.category === category;
        if (block === undefined) return true;
        return tensor.name.includes(`blk.${block}.`) || tensor.name.includes(`layers.${block}.`) || tensor.name.includes(`layer.${block}.`);
    }).slice(0, 14);
    const tensors = matches && matches.length > 0 ? matches : MOCK_TENSORS.map((name, index) => ({
        name: block === undefined ? name : `blk.${block}.${name}`,
        dtype: index < 10 ? 'Q4_0' : 'F32',
        shape: index < 7 ? [3584, 3584] : [3584],
        bytes: index < 7 ? 18_874_368 : 14_336,
        chunkStart: block === undefined ? index : block * 31 + index,
        chunkEnd: block === undefined ? index + 1 : block * 31 + index + 1,
    }));
    return <div className={s.tensorDetails}>
        {tensors.map(tensor => <div key={tensor.name}>
            <strong>{tensor.name}</strong>
            <span>{tensor.dtype} · [{tensor.shape.join(' × ')}]</span>
            <span>{formatBytes(tensor.bytes)}</span>
            <small>leaves {tensor.chunkStart}–{tensor.chunkEnd}</small>
        </div>)}
    </div>;
}

function MetricCard({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: 'green' | 'blue' | 'amber' }) {
    return <article className={s.card}><span className={s.metricLabel}>{label}</span><strong className={clsx(s.metricValue, s[`metric_${tone}`])}>{value}</strong><small>{detail}</small></article>;
}

function SignalRow({ label, value, status }: { label: string; value: string; status: EvidenceStatus }) {
    return <div><span>{label}</span><strong>{value}</strong><StatusPill status={status} /></div>;
}

function TraceNode({ icon, label, value }: { icon: typeof faCube; label: string; value: string }) {
    return <div><FontAwesomeIcon icon={icon} /><span>{label}</span><strong>{value}</strong></div>;
}

function Outcome({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: 'green' | 'blue' | 'amber' | 'slate' }) {
    return <div className={clsx(s.outcome, s[`outcome_${tone}`])}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}

function MonitorTrigger({ icon, title, detail, state }: { icon: typeof faCube; title: string; detail: string; state: string }) {
    return <div><FontAwesomeIcon icon={icon} /><div><strong>{title}</strong><span>{detail}</span></div><StatusPill status="verified">{state}</StatusPill></div>;
}

function TimelineEvent({ time, title, detail, tone }: { time: string; title: string; detail: string; tone: 'green' | 'blue' | 'amber' }) {
    return <div className={s.timelineEvent}><i className={s[`timeline_${tone}`]} /><span>{time}</span><div><strong>{title}</strong><p>{detail}</p></div></div>;
}

function TrustPlane({ label, score, status, detail }: { label: string; score: string; status: EvidenceStatus; detail: string }) {
    return <div><div><span>{label}</span><StatusPill status={status} /></div><strong>{score}<small>/100</small></strong><p>{detail}</p></div>;
}

function DecisionList({ tone, title, items }: { tone: 'green' | 'amber' | 'red'; title: string; items: string[] }) {
    const icon = tone === 'green' ? faCheck : tone === 'red' ? faXmark : faTriangleExclamation;
    return <section className={clsx(s.card, s.decisionList, s[`decision_${tone}`])}><h2>{title}</h2><ul>{items.map(item => <li key={item}><FontAwesomeIcon icon={icon} /><span>{item}</span></li>)}</ul></section>;
}

function inferLayerCount(artifact: ArtifactAnalysis): number {
    let max = -1;
    for (const tensor of artifact.tensors) {
        const match = tensor.name.match(/(?:blk|layers?|blocks?)\.(\d+)\./i);
        if (match) max = Math.max(max, Number(match[1]));
    }
    return max >= 0 ? max + 1 : 0;
}

function inferQuantization(artifact: ArtifactAnalysis): string {
    const counts = new Map<string, number>();
    for (const tensor of artifact.tensors) counts.set(tensor.dtype, (counts.get(tensor.dtype) ?? 0) + 1);
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([type, count]) => `${type}×${count}`).join(' · ') || 'unknown';
}

function matchingCount(artifact: ArtifactAnalysis, category: TensorCategory): number {
    return artifact.tensors.filter(tensor => tensor.category === category).length;
}

function categoryBytes(artifact: ArtifactAnalysis, category: TensorCategory): string {
    return formatBytes(artifact.tensors.filter(tensor => tensor.category === category).reduce((sum, tensor) => sum + tensor.bytes, 0));
}
