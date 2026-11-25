# ADR-002: Deterministic Evidence-Grounded RCA Before Optional Local LLM Narration

## Status
Accepted

## Context
Relying directly on an LLM to diagnose production data incidents introduces non-determinism, fabricated trace/signal references (hallucinated evidence), latency spikes, and model-licensing overhead.

## Decision
1. Implement **100% deterministic correlation and Top-K root-cause candidate ranking** first, driven by OpenLineage graph ancestry, temporal precedence (`event_time_ms`), deployment/schema diffs, and false-positive persistence filtering.
2. Verify every single cited pointer (`signal_id`, `span_id`, `commit_version`, `lineage_edge`) against persisted rows read back from Apache Iceberg V2, guaranteeing a measured `hallucinated_evidence_rate = 0.0%`.
3. Provide a pluggable `OptionalLocalLLMAdapter` targeting `ollama/ollama:0.40.18` (configured under an optional `llm` Compose profile), **disabled by default** (`ENABLE_LOCAL_LLM=false`), restricted strictly to summarizing already-verified evidence bundles, and never granted tool-execution authority. No pretrained LLM weights are downloaded or redistributed.

## Consequences
- **Benefits:** Sub-millisecond deterministic diagnosis (`p95 < 1 ms`), zero hallucinated citations, zero GPU/weight dependency for local testing, and strict open-source license hygiene.
- **Tradeoffs:** Novel failure modes outside the modeled causal rules fall back to `pipeline_execution_failure` with conservative `bounded_retry_task` guidance rather than open-ended synthesis until new causal rules are added.
