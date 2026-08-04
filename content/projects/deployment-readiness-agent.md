---
title: "The Deployment Readiness Agent"
date: 2026-08-03
tags: ["LangGraph", "Pydantic", "Agents", "Evals", "RTLS"]
summary: "A three-agent pipeline that drafts hospital deployment-readiness reports from synthetic RTLS telemetry, built around a single constraint: the model is not allowed to state a root cause without a source note."
---

## Overview

RTLS (real-time location system) deployments in hospitals depend on wireless tags being heard reliably by multiple access points. When they aren't, location tracking degrades — and pre-deployment audits exist to catch that before go-live.

The audit workflow has a routine shape: pull telemetry from the location engine, aggregate per-tag signal statistics, compare them against zone-specific readiness thresholds, and produce a report that surfaces the failing tags with recommended actions.

This project is a three-agent pipeline that automates the draft version of that report from synthetic telemetry, technician field notes, and a YAML readiness spec. It is built around a single constraint that shaped every design decision: **the language model is not permitted to state a root cause unless a human technician documented it first.**

## Where the LLM belongs, and where it doesn't

A common failure mode in agent systems is routing everything through the model. The math, the parsing, the comparisons — all of it. It costs more, runs slower, and introduces a chance to be wrong on operations that were previously deterministic.

The pipeline splits work by whether the task is genuinely a language problem:

**Deterministic Python:** parsing the engine export, aggregating per-tag statistics over the evaluation window, comparing values against the readiness spec, emitting typed violations.

**LLM:** extracting structured facts from freeform technician notes, attributing violations to note-stated causes, and generating the final report prose.

The aggregation stage is the clearest case for keeping the model out. Per tag, the pipeline reduces hundreds of engine records down to a handful of numbers using standard library statistics:

```python
def _compute_aggregate(entry, records, window_start, window_end):
    total = len(records)

    ap_counts = [len(r.heard_by) for r in records]
    median_ap_count = float(statistics.median(ap_counts))

    best_rssi_per_record = [
        max(ap.rssi_dbm for ap in r.heard_by) for r in records
    ]
    median_best_rssi = float(statistics.median(best_rssi_per_record))

    mean_confidence = sum(r.location_confidence for r in records) / total

    zone_matches = sum(
        1 for r in records
        if r.engine_zone_estimate == entry.assigned_zone
    )
    zone_match_pct = zone_matches / total
    ...
```

Threshold evaluation is similarly deterministic. A per-zone-type YAML spec defines the readiness criteria (critical-care zones have stricter requirements than ancillary ones), and violations are emitted as typed objects for the analysis stage to consume.

Where the LLM does belong is where the input is unstructured language. Technician notes captured during a walk-through have exactly the shape LLMs handle well:

> *"TAG-0031 portable xray unit — lead apron storage rack directly adjacent to tag mount point on the machine frame. heavy shielding material likely attenuating signal. discussed relocating tag to handle bar. no ticket yet will follow up"*

Extracting which tag, what cause, and any suggested action from that is a genuine language task. The extraction is constrained by a schema:

```python
class NoteFacts(BaseModel):
    note_id:          str
    referenced_tags:  list[str]     # normalized to "MRW-TAG-XXXX"
    referenced_zones: list[str]     # normalized zone names
    stated_cause:     str | None    # verbatim-ish; None if none stated
    ticket_refs:      list[str]
    suggested_action: str | None
    unresolvable:     bool = False
```

## The no-fabricated-causes constraint

Fabricated root causes are the failure mode this project is organized around preventing. In a domain where a downstream action depends on the reported cause, a plausible-sounding invention is worse than an honest "unknown." The system is designed such that a cause in the final report is traceable to a specific technician note or the report says the cause is unknown.

That constraint is enforced at three layers.

**Layer 1 — the prompt** for the note-extraction call is explicit about what a cause is and is not:

> *"stated_cause is the technician's explanation of WHY something is happening — not just WHAT. NEVER invent, infer, or guess a cause. If the technician did not explicitly state why something is happening, stated_cause MUST be null."*

**Layer 2 — a Pydantic validator** on the `Gap` model rejects any finding where a stated cause exists without a source note attached:

```python
class Gap(BaseModel):
    severity:           Literal["critical", "high", "medium", "low"]
    tag_ids:            list[str]
    zone:               str
    violation_types:    list[ViolationType]
    finding:            str
    stated_cause:       str | None    # only from a technician note
    source_note_ids:    list[str]     # empty iff stated_cause is None
    ticket_refs:        list[str]
    recommended_action: str

    @model_validator(mode="after")
    def cause_requires_source(self) -> "Gap":
        if self.stated_cause is not None and len(self.source_note_ids) == 0:
            raise ValueError(
                "stated_cause is set but source_note_ids is empty. "
                "Every stated cause must trace to a note ID. "
                "If no note explains this violation, set stated_cause to None."
            )
        return self
```

Malformed model output raises on construction. The LLM call is retried once with the validation error appended to the prompt.

**Layer 3 — an evaluation** run against every generated report checks that no cause in the prose is untraceable to a note:

```python
class JudgeVerdict(BaseModel):
    all_gaps_covered:       bool
    fabricated_causes:      list[str]   # required to be []
    passing_tags_mentioned: bool
    unknown_causes_handled: bool
    jargon_violations:      list[str]
    score:                  int         # 0–10
```

A non-empty `fabricated_causes` field fails the case.

## Output

The constraint produces a report where the presence or absence of a cause is meaningful rather than cosmetic. Two findings from a demo run, with different note coverage:

> ### SurgSuite-1 — MRW-TAG-0031 (portable x-ray)
> Median best RSSI **−81 dBm** across two access points, against the critical-care threshold of −75 dBm. Mean location confidence **0.39**, against the 0.80 threshold. The field technician noted that the lead apron storage rack sits directly adjacent to the tag mount point on the machine frame, and identified the heavy shielding material as the likely cause of signal attenuation. Relocation of the tag to the machine's handle bar was suggested on-site.
>
> **Recommended action:** implement the field technician's suggested tag relocation and re-measure signal after the move.
>
> ### NursingUnit-B — MRW-TAG-0030 (infusion pump)
> Median AP count **1.0**, against the critical-care requirement of at least 3 access points. Location confidence is correspondingly low.
>
> **Recommended action:** cause unknown — on-site investigation required to determine whether the deficit is due to AP placement, hardware failure, or physical obstruction in the zone.

Both findings are correctly flagged by the threshold engine. Only one has a cited cause, because only one had a technician note attached to it in the source data.

## Evaluation

The pipeline is non-deterministic in its LLM stages, so correctness has to be measured rather than assumed.

Deterministic stages (aggregation, threshold evaluation) are covered by exact-match tests against hand-authored expected outputs. Given a fixed input dataset, the aggregation function's output is a stable structure that can be diffed byte-for-byte.

The report stage uses a second LLM configured as a judge, structured against `JudgeVerdict`. It scores coverage of the underlying gaps, checks for fabricated causes, and flags jargon that wasn't glossed for a non-technical reader. Each run is logged alongside the prompt version hash, so regressions on a prompt change are detectable immediately.

The most useful test case in the harness is one where a field note describes a problem in the *wrong* zone from where it was written. It exists specifically to check that the attribution stage doesn't cross-wire causes to violations that happen to co-occur in the same run.

## Human review

The pipeline produces a draft. Sign-off remains with the engineer reviewing it. Corrections captured during that review are the natural training signal for a future version, and a formal approval checkpoint is planned as the next iteration.

## What's next

- **Critic agent** reviewing the writer's draft before human review, with an eval that specifically tests whether it catches injected errors rather than passing everything through
- **Approval checkpoint** via LangGraph's interrupt mechanism, with state checkpointed to disk between the draft and the human decision
- **Additional input formats** beyond the current synthetic engine-export shape

---

*Built with synthetic data modeled on real-time location deployments. No real client data, facility, or telemetry was used.*
