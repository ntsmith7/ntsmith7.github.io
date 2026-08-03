---
title: "The Deployment Readiness Agent"
date: 2026-08-03
tags: ["LangGraph", "Pydantic", "Agents", "Evals", "RTLS"]
summary: "A three-agent pipeline that drafts hospital deployment-readiness reports from synthetic RTLS telemetry — built around a single rule: the AI is not allowed to guess a root cause."
---

## Overview

Part of my job is walking into hospitals and auditing their real-time location systems — the wireless networks that track where an infusion pump or a patient-protection tag actually is inside the building. I review telemetry from the location engine, figure out which tags aren't signaling reliably enough for the system to trust their position, and write it all up in a report a non-technical stakeholder can act on.

It's careful, valuable work. It's also, in parts, a grind: aggregating hundreds of readings per tag, checking them against thresholds, and translating "median RSSI of −81 dBm across two access points" into a sentence a nurse manager understands.

So I tried to automate the grind — not to replace the engineer, but to find the exact line where an AI agent *shouldn't* be trusted.

## The temptation to route everything through the model

The naive version of this project is one big prompt: dump the telemetry and the field notes into a language model, ask for a readiness report, done.

That version fails the way LLMs famously fail. It will confidently tell you a tag has weak signal *because of a concrete wall it invented*, when the real data says nothing about walls at all. In a hospital life-safety context, a plausible-sounding fabricated cause is worse than no cause at all.

So the first real design decision was about restraint: **what should the language model actually be allowed to do?**

## Drawing the line: language problems vs. everything else

I split the system into three specialized agents, and inside the first two, I split the work again — deterministic Python for anything mathematical, the LLM only for genuine language problems.

The **discovery agent** parses the raw engine export and aggregates each tag's hundreds of readings into a handful of summary numbers. Median APs that heard it, median best signal strength, the largest gap in its reporting, how often the engine placed it in the assigned zone. None of that touches the model:

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

A median is a median. Asking an LLM to compute one just adds cost and a chance to be wrong.

But that same agent *does* use the LLM for one thing: reading the technician's field notes. Those notes are gloriously messy:

> *"TAG-0031 portable xray unit — lead apron storage rack directly adjacent to tag mount point on the machine frame. heavy shielding material likely attenuating signal. discussed relocating tag to handle bar. no ticket yet will follow up"*

Turning that into structured data — which tag, what cause, any ticket, any suggested action — is a real language problem. So the model gets a strict, schema-shaped job:

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

The **analysis agent** does the same dance. A deterministic threshold engine compares each tag's stats against a per-zone-type spec — a critical-care unit has stricter requirements than a supply closet — and emits typed violations. Then the LLM does the part only language understanding can: matching each violation to the technician note that explains it and grouping related problems into a coherent finding.

The **writer agent** is the one fully-LLM stage, because turning structured findings into readable prose for a non-technical reader is exactly what these models are for.

The lesson, and the thing I'd emphasize to anyone building agent systems today: **using an LLM well is mostly about deciding what *not* to use it for.**

## The rule that made it trustworthy: no guessing

Here's the constraint the whole project is built around:

> The AI is never allowed to state a root cause unless a human technician wrote it down first.

If the data shows a tag has weak signal and a field note explains why, the report cites that cause and attributes it to the technician. If there's no note, the report says the cause is unknown and on-site investigation is needed. It never fills the gap with a plausible guess.

I enforced this at three layers, because a prompt instruction alone is not enforcement.

**Layer 1 — the prompts** never invite the model to infer or diagnose. The extraction system prompt is explicit:

> *"stated_cause is the technician's explanation of WHY something is happening — not just WHAT. NEVER invent, infer, or guess a cause. If the technician did not explicitly state why something is happening, stated_cause MUST be null."*

**Layer 2 — a Pydantic validator** on the final `Gap` model rejects any finding that has a stated cause but no source note attached to it:

```python
class Gap(BaseModel):
    severity:           Literal["critical", "high", "medium", "low"]
    tag_ids:            list[str]
    zone:               str
    violation_types:    list[ViolationType]
    finding:            str
    stated_cause:       str | None    # ONLY from a technician note; never invented
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

Malformed output doesn't get through. It raises, and the pipeline retries the LLM call with the validation error appended to the prompt.

**Layer 3 — an automated evaluation** checks every generated report for causes that can't be traced back to a note:

```python
class JudgeVerdict(BaseModel):
    all_gaps_covered:       bool
    fabricated_causes:      list[str]   # MUST be []
    passing_tags_mentioned: bool
    unknown_causes_handled: bool
    jargon_violations:      list[str]
    score:                  int         # 0–10
```

A non-empty `fabricated_causes` list fails the build. That third layer is the one most portfolio projects skip, and it's the one I'd argue matters most.

## What the output actually looks like

The three layers pay off in the report. Here are two side-by-side findings the pipeline produced on the demo dataset — one with a cited technician cause, one without:

> ### SurgSuite-1 — MRW-TAG-0031 (portable x-ray)
> Median best RSSI **−81 dBm** across two access points, against the critical-care threshold of −75 dBm. Mean location confidence **0.39**, against the 0.80 threshold. The field technician noted that the lead apron storage rack sits directly adjacent to the tag mount point on the machine frame, and identified the heavy shielding material as the likely cause of signal attenuation. Relocation of the tag to the machine's handle bar was suggested on-site.
>
> **Recommended action:** implement the field technician's suggested tag relocation and re-measure signal after the move.
>
> ### NursingUnit-B — MRW-TAG-0030 (infusion pump)
> Median AP count **1.0**, against the critical-care requirement of at least 3 access points. Location confidence is correspondingly low.
>
> **Recommended action:** cause unknown — on-site investigation required to determine whether the deficit is due to AP placement, hardware failure, or physical obstruction in the zone.

Same report, same pipeline, two different tags: one gets a rich causal explanation because a technician documented it, the other gets a plain statement of the numbers and an honest call for investigation. That's the entire thesis of the project on one page.

## How I know it works

An agent that produces plausible output is not the same as an agent that produces *correct* output. The only way to tell the difference is to measure it.

The evaluation harness has two kinds of checks. For the deterministic stages — the aggregation and threshold math — I hand-authored the correct answer for a set of test cases and the pipeline's output has to match exactly. For the report itself, where there's no single correct answer, I used a second LLM as a judge, structured against `JudgeVerdict`: does the report cover every real problem, does it invent any causes, does it explain jargon, does it acknowledge the tags that passed?

Every run gets logged, tagged with the prompt version that produced it. When I tweak a prompt to fix one thing, I can immediately see whether I broke something else. Same instinct as a regression test suite — just pointed at a non-deterministic system.

The most useful test case wasn't the happy path. It was the one where I fed the system a note that explained the *wrong* tag's problem, to see if it would cross-wire the attribution. Watching it either resist that or fall for it told me more about whether the design worked than any clean run ever did.

## Where a human still belongs

The pipeline produces a *draft*. A person still reviews it, corrects it, and owns what goes to the client — and every correction they make is exactly the kind of data that would make the next version better.

That's not a limitation I'm apologizing for. It's the point. The valuable thing an experienced engineer does on a site visit isn't the arithmetic — it's the judgment. The system takes over the arithmetic and the first-draft translation, and leaves the judgment where it belongs.

## What's next

The current version is deliberately narrow: one scenario, three agents, a linear flow, and a hard rule against guessing. The natural next steps are a critic agent that reviews the writer's draft before a human sees it, and a formal approval checkpoint where the pipeline pauses for sign-off before anything ships. Both are interesting precisely because they're easy to do badly — a critic that rubber-stamps everything is worse than no critic at all — so they'll get the same measure-everything treatment.

If there's a single takeaway from building this: the impressive part of an AI agent isn't how much it can do. It's how clearly you've drawn the line around what it's *allowed* to do — and whether you can prove it stays on the right side of that line.

---

*Built with synthetic data modeled on real-time location deployments. No real client data, facility, or telemetry was used.*
