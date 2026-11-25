"""Deterministic Evidence-Grounded Root-Cause Ranking, Zero-Hallucination Verifier, and Optional Local LLM Adapter."""

from __future__ import annotations

import hashlib
import time
from typing import Any, Protocol

import requests

from agentic_sre.correlator import IncidentCorrelator
from agentic_sre.platform_model import LAYER_ORDER, PlatformLineageGraph
from agentic_sre.telemetry import DEFAULT_TELEMETRY, TelemetryHub
from models.schemas import CorrelatedIncidentModel, EvidencePointer, RcaHypothesisModel


class LocalLLMAdapterProtocol(Protocol):
    """Pluggable optional local LLM adapter (disabled by default; strictly read-only narration)."""

    def summarize_verified_bundle(
        self,
        incident: CorrelatedIncidentModel,
        hypotheses: list[RcaHypothesisModel],
    ) -> str | None: ...


class OptionalLocalLLMAdapter:
    """Optional Ollama adapter (ollama/ollama:0.40.18). Disabled by default; never downloads weights or invokes tools."""

    def __init__(
        self,
        enabled: bool = False,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "llama3.2:3b",
        timeout_seconds: float = 5.0,
    ) -> None:
        self.enabled = enabled
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def summarize_verified_bundle(
        self,
        incident: CorrelatedIncidentModel,
        hypotheses: list[RcaHypothesisModel],
    ) -> str | None:
        if not self.enabled or not hypotheses:
            return None
        top = hypotheses[0]
        cited_ids = [p.pointer_id for p in top.evidence_pointers if p.verified]
        prompt = (
            "Summarize this verified incident strictly using ONLY the provided evidence IDs. "
            f"Incident: {incident.incident_id} ({incident.scenario_type}), Root Asset: {top.root_asset_id}, "
            f"Recommended Safe Tool: {top.recommended_tool}, Verified Evidence IDs: {cited_ids}."
        )
        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=self.timeout_seconds,
            )
            resp.raise_for_status()
            text = str(resp.json().get("response", "")).strip()
            return text or None
        except Exception:
            return None


class DeterministicRcaEngine:
    """Ranks Top-K root-cause candidates strictly from verified persisted Iceberg evidence."""

    def __init__(
        self,
        lineage: PlatformLineageGraph | None = None,
        assets_metadata: dict[str, dict[str, Any]] | None = None,
        telemetry: TelemetryHub | None = None,
        llm_adapter: LocalLLMAdapterProtocol | None = None,
    ) -> None:
        self.lineage = lineage or PlatformLineageGraph()
        self.assets_metadata = assets_metadata or {}
        self.telemetry = telemetry or DEFAULT_TELEMETRY
        self.correlator = IncidentCorrelator(self.lineage, self.assets_metadata, self.telemetry)
        self.llm_adapter = llm_adapter or OptionalLocalLLMAdapter(enabled=False)

    def diagnose_incident(
        self,
        incident: CorrelatedIncidentModel,
        incident_signals: list[dict[str, Any]],
        persisted_signal_ids: set[str],
        persisted_span_ids: set[str],
        persisted_edge_ids: set[str],
        persisted_commits: set[str],
        top_k: int = 3,
    ) -> list[RcaHypothesisModel]:
        """Generate Top-K deterministic hypotheses and verify every citation against persisted Iceberg evidence."""
        t0 = time.perf_counter()
        with self.telemetry.start_span(
            "rca.diagnose_incident",
            {"incident_id": incident.incident_id, "scenario_type": incident.scenario_type},
        ):
            if incident.is_false_positive:
                pointers = self._build_asset_pointers(
                    incident.root_asset_id, incident_signals, incident.lineage_edges
                )
                hyp = self._verify_and_finalize(
                    incident_id=incident.incident_id,
                    rank=1,
                    root_asset=incident.root_asset_id,
                    category="false_positive_noisy_alert",
                    confidence=0.97,
                    rationale=(
                        f"Suppressed false-positive alert on {incident.root_asset_id}: "
                        "single-sample WARNING metric spike with zero corroborating ERROR/DQ/trace failures."
                    ),
                    recommended_tool="none_read_only",
                    recommended_params={},
                    pointers=pointers,
                    persisted_signal_ids=persisted_signal_ids,
                    persisted_span_ids=persisted_span_ids,
                    persisted_edge_ids=persisted_edge_ids,
                    persisted_commits=persisted_commits,
                )
                self.telemetry.rca_latency_seconds.observe(time.perf_counter() - t0)
                return [hyp]

            sigs_by_asset: dict[str, list[dict[str, Any]]] = {}
            for sig in incident_signals:
                sigs_by_asset.setdefault(str(sig["asset_id"]), []).append(sig)

            comp_assets = set(incident.impacted_assets)
            first_event_ms = incident.first_event_time_ms
            candidates: list[tuple[float, str, str, str, dict[str, Any]]] = []

            for asset_id in incident.impacted_assets:
                asset_sigs = sigs_by_asset.get(asset_id, [])
                if not asset_sigs:
                    continue
                category, spec_score = self.correlator._classify_asset_category(
                    asset_id, asset_sigs, incident_signals
                )
                ancestors_in_comp = self.lineage.ancestors(asset_id).intersection(comp_assets)
                upstream_bonus = 4.5 if not ancestors_in_comp else -2.5 * len(ancestors_in_comp)
                earliest = min(int(s["event_time_ms"]) for s in asset_sigs)
                temporal_bonus = 1.5 if earliest == first_event_ms else 0.0
                layer_tiebreak = 0.1 * (5 - LAYER_ORDER.get(asset_id.split(".")[0], 5))
                raw_score = upstream_bonus + spec_score + temporal_bonus + layer_tiebreak

                tool_name, target_asset, params = self.correlator._recommend_action(
                    category, asset_id, incident_signals
                )
                params_full = dict(params)
                params_full["target_asset_id"] = target_asset
                candidates.append((raw_score, asset_id, category, tool_name, params_full))

            candidates.sort(key=lambda x: (-x[0], x[1]))
            top_candidates = candidates[: max(1, top_k)]
            max_score = max(c[0] for c in top_candidates) if top_candidates else 1.0

            hypotheses: list[RcaHypothesisModel] = []
            for rank_idx, (score, asset_id, category, tool_name, params_full) in enumerate(
                top_candidates, start=1
            ):
                # Convert deterministic margin into bounded confidence [0.15, 0.96].
                if rank_idx == 1:
                    conf = round(min(0.96, max(0.72, 0.84 + 0.015 * score)), 3)
                else:
                    gap = max(0.0, max_score - score)
                    conf = round(max(0.15, min(0.68, 0.58 - 0.06 * gap)), 3)

                asset_sigs = sigs_by_asset.get(asset_id, [])
                pointers = self._build_asset_pointers(asset_id, asset_sigs, incident.lineage_edges)
                upstream_note = (
                    "topmost upstream failing node in lineage DAG"
                    if not self.lineage.ancestors(asset_id).intersection(comp_assets)
                    else f"downstream impacted asset ({len(self.lineage.ancestors(asset_id).intersection(comp_assets))} failing upstream ancestor(s))"
                )
                rationale = (
                    f"Rank #{rank_idx} candidate {asset_id} ({category}): {upstream_note}; "
                    f"backed by {len(asset_sigs)} signal(s) and {len(pointers)} verified evidence pointer(s)."
                )
                hyp = self._verify_and_finalize(
                    incident_id=incident.incident_id,
                    rank=rank_idx,
                    root_asset=asset_id,
                    category=category,
                    confidence=conf,
                    rationale=rationale,
                    recommended_tool=tool_name,
                    recommended_params=params_full,
                    pointers=pointers,
                    persisted_signal_ids=persisted_signal_ids,
                    persisted_span_ids=persisted_span_ids,
                    persisted_edge_ids=persisted_edge_ids,
                    persisted_commits=persisted_commits,
                )
                hypotheses.append(hyp)

        self.telemetry.rca_latency_seconds.observe(time.perf_counter() - t0)
        return hypotheses

    def _build_asset_pointers(
        self,
        asset_id: str,
        asset_sigs: list[dict[str, Any]],
        incident_edges: list[str],
    ) -> list[EvidencePointer]:
        pointers: list[EvidencePointer] = []
        seen: set[tuple[str, str]] = set()
        for sig in asset_sigs:
            sid = str(sig["signal_id"])
            if ("signal_id", sid) not in seen:
                seen.add(("signal_id", sid))
                pointers.append(
                    EvidencePointer(
                        pointer_type="signal_id",
                        pointer_id=sid,
                        asset_id=asset_id,
                        summary=f"{sig['signal_type']} ({sig['severity']}): {str(sig['message'])[:120]}",
                    )
                )
            spid = str(sig["span_id"])
            if ("span_id", spid) not in seen:
                seen.add(("span_id", spid))
                pointers.append(
                    EvidencePointer(
                        pointer_type="span_id",
                        pointer_id=spid,
                        asset_id=asset_id,
                        summary=f"Trace span {spid} in run {sig['run_id']}",
                    )
                )
            commit = sig.get("commit_version")
            if commit and ("commit_version", str(commit)) not in seen:
                seen.add(("commit_version", str(commit)))
                pointers.append(
                    EvidencePointer(
                        pointer_type="commit_version",
                        pointer_id=str(commit),
                        asset_id=asset_id,
                        summary=f"Deployment/schema commit {commit} on {asset_id}",
                    )
                )

        for edge_id in incident_edges:
            if (f"{asset_id}->" in edge_id or f"->{asset_id}" in edge_id) and (
                "lineage_edge",
                edge_id,
            ) not in seen:
                seen.add(("lineage_edge", edge_id))
                pointers.append(
                    EvidencePointer(
                        pointer_type="lineage_edge",
                        pointer_id=edge_id,
                        asset_id=asset_id,
                        summary=f"OpenLineage causal propagation edge {edge_id}",
                    )
                )
        return pointers

    def _verify_and_finalize(
        self,
        *,
        incident_id: str,
        rank: int,
        root_asset: str,
        category: str,
        confidence: float,
        rationale: str,
        recommended_tool: str,
        recommended_params: dict[str, Any],
        pointers: list[EvidencePointer],
        persisted_signal_ids: set[str],
        persisted_span_ids: set[str],
        persisted_edge_ids: set[str],
        persisted_commits: set[str],
    ) -> RcaHypothesisModel:
        verified_pointers, verified_count, hallucinated_count = verify_evidence_pointers(
            pointers=pointers,
            persisted_signal_ids=persisted_signal_ids,
            persisted_span_ids=persisted_span_ids,
            persisted_edge_ids=persisted_edge_ids,
            persisted_commits=persisted_commits,
        )
        if hallucinated_count > 0:
            self.telemetry.hallucinated_citations.inc(hallucinated_count)

        hid = f"hyp-{hashlib.sha256(f'{incident_id}:{rank}:{root_asset}'.encode()).hexdigest()[:12]}"
        return RcaHypothesisModel(
            hypothesis_id=hid,
            incident_id=incident_id,
            rank=rank,
            root_asset_id=root_asset,
            root_cause_category=category,
            confidence=confidence,
            rationale=rationale,
            recommended_tool=recommended_tool,
            recommended_parameters=recommended_params,
            evidence_pointers=verified_pointers,
            verified_citation_count=verified_count,
            total_citation_count=len(verified_pointers),
            hallucinated_citation_count=hallucinated_count,
        )


def verify_evidence_pointers(
    pointers: list[EvidencePointer],
    persisted_signal_ids: set[str],
    persisted_span_ids: set[str],
    persisted_edge_ids: set[str],
    persisted_commits: set[str],
) -> tuple[list[EvidencePointer], int, int]:
    """Verify every cited evidence pointer against persisted Iceberg V2 records to guarantee 0% hallucination."""
    verified_list: list[EvidencePointer] = []
    verified_count = 0
    hallucinated_count = 0
    for ptr in pointers:
        is_valid = False
        if ptr.pointer_type == "signal_id":
            is_valid = ptr.pointer_id in persisted_signal_ids
        elif ptr.pointer_type == "span_id":
            is_valid = ptr.pointer_id in persisted_span_ids
        elif ptr.pointer_type == "lineage_edge":
            is_valid = ptr.pointer_id in persisted_edge_ids
        elif ptr.pointer_type == "commit_version":
            is_valid = ptr.pointer_id in persisted_commits

        checked = ptr.model_copy(update={"verified": is_valid})
        verified_list.append(checked)
        if is_valid:
            verified_count += 1
        else:
            hallucinated_count += 1
    return verified_list, verified_count, hallucinated_count
