---
title: "A Citation Isn't Proof: Building Evidence Checks into AI Workflows"
date: 2026-10-20
lastmod: 2026-10-20
draft: false
tags: ["AI", "Agents", "Evaluation", "RTLS"]
summary: "All 27 assessments matched the expected labels, but some explanations were still wrong. Code and examples show what source checks, claim support, and relevance can actually establish."
description: "Practical code examples for validating evidence in AI workflows, using synthetic RTLS cases and saved model responses to separate source integrity, claim support, and relevance."
---

One evaluation batch for my Deployment Readiness Agent returned the expected labels in all **27 assessments**. Some of its explanations were still wrong.

A model correctly rejected an unsupported claim, then gave an unsupported reason for rejecting it. Another response described minutes as seconds. A score based only on the labels missed both problems.

That exposed a limitation in how I was checking the workflow: I could verify that a response had the expected structure and classifications without verifying the claims in its explanation.

The examples below come from the second version of my [Deployment Readiness Agent](/projects/deployment-readiness-agent/), which combines real-time location system (RTLS) measurements and technician notes into an assessment for review. The facilities, equipment tags, measurements, and notes are synthetic. The model responses are saved evaluation outputs from those synthetic cases.

## A correct label can have an incorrect explanation

One case proposed this claim:

> An AP maintenance shutdown caused the reporting gap.

Here, AP means wireless access point. The cited note discussed an outdated zone assignment and ended with:

> No AP maintenance was recorded.

The model returned these labels, shown exactly as saved:

```json
{
  "claim_support": "unsupported",
  "violation_relevance": "relevant"
}
```

Both matched the authored expectations. The note did not establish a maintenance shutdown, while the proposed shutdown concerned the missing updates being investigated.

But the first sentence of the model's support explanation said:

> The note states "No AP maintenance was recorded," which contradicts the claimed cause of an AP maintenance shutdown.

Missing documentation does not establish that maintenance did not happen. The claim lacked supporting evidence; the note did not contradict it. That distinction matters when someone uses the assessment to decide what to investigate next.

The [saved evaluation evidence](/files/agent-evidence-checks/evaluation-evidence.json) contains all six runs: nine authored cases repeated three times, producing 27 matching label pairs with no request errors. This is a small historical evaluation, not a general accuracy benchmark or a measurement of the latest prompts.

## A valid source reference leaves several questions open

I separate validation into four questions:

1. **Structure:** Does the response contain the required fields and allowed values?
2. **Source integrity and scope:** Does the note exist, does the quotation appear in it, and does its declared site, tag, or zone scope apply?
3. **Claim support:** Does the full note support the unchanged claim, including its certainty and qualifications?
4. **Relevance:** Does that claim concern the measured problem?

The first two are mechanical checks in this project. The last two are model judgments, which can be wrong even when their outputs pass schema validation.

An exact quotation is a useful example. This runnable Python snippet uses text from an evaluation case:

```python
note = (
    "For MRW-TAG-0031, we ruled out the hypothesis that "
    "rack shielding caused the weak signal. "
    "The cause remains unknown."
)
quote = "rack shielding caused the weak signal"

assert quote in note  # Passes: the quoted text exists.
```

The check works as intended. It establishes that the quotation is present. It does not account for the words "ruled out," which reverse the meaning of the extracted phrase. The support assessment must read the full note.

Even a correctly supported claim has another limit: **faithfulness to a source does not establish that the source is true.** A technician can be mistaken. This workflow assesses whether a claim follows from a note; it does not independently confirm the event described.

## Separate the questions and their inputs

Support and relevance can disagree. A claim that an access-point outage caused missing updates is relevant to a reporting gap, even when its cited note provides no evidence of an outage. Conversely, a note can support a claim that a loose caster made a cart wobble without identifying any connection to weak radio reception.

I give those judgments separate model requests. These are the two payloads from `assess_cause`, shown with local variable names for readability; transport, response validation, and retry handling are omitted:

```python
support_payload = {
    "stated_cause": facts.stated_cause,
    "cause_quote": facts.cause_quote,
    "note": source.model_dump(mode="json"),
}

relevance_payload = {
    "stated_cause": facts.stated_cause,
    "violation": violation_with_units(violation),
}
```

Both receive the same unchanged claim. Support receives the full note. Relevance receives the measured violation. Neither request receives the other's judgment or conversation history. The source note may itself mention measurements; it is preserved intact.

This separation gives each request a narrower task and makes errors easier to inspect. It adds a model call, and both judgments remain fallible. Two calls do not constitute independent confirmation of the event.

The workflow also preserves valid negative and uncertain judgments. Malformed assessment output gets one retry; an answer of "unsupported" does not trigger repeated attempts to obtain a positive answer.

## Supply the facts the model needs

The units error exposed an input-design problem on my side. The earlier payload supplied an observed value of `300` and a threshold of `15`, but no explicit unit field. The underlying metric was measured in minutes. One saved explanation called it "a 300s gap against a 15s threshold."

The model supplied an unsupported interpretation where the input contract left information implicit.

The current `violation_with_units` helper attaches metric and unit metadata before the relevance request. For a reporting gap, the relevant fields look like this; identifiers are omitted here:

```json
{
  "violation_type": "REPORT_GAP",
  "observed_value": 300.0,
  "threshold": 15.0,
  "measurement": {
    "metric": "max_gap_minutes",
    "unit": "minutes"
  }
}
```

The unit applies to both values. This supplies the context needed to interpret them, though it cannot guarantee that the model will use it correctly.

Following the maintenance example, I also added a required support reason: missing evidence, contradiction, overstated certainty, explicit support, or an ambiguous reference. Code rejects incompatible label/reason combinations. A combination can still be structurally valid and semantically wrong.

That is why evaluation needs more than one check. Code tests verify mechanics. Semantic cases compare judgments and reasons with authored expectations. Review of the reported explanations checks source meaning, uncertainty, and units. A matching label does not excuse an invented statement elsewhere in the response.

## Preserve the missing connection in the final output

The same boundary matters when presenting findings. In the fictional NursingUnit-B assessment, two wireless equipment tags each had a five-hour interval without recorded updates, against a configured 15-minute limit. A technician note described staff moving equipment into a utility room with poor access-point coverage.

An illustrative inference would be that those tags entered the room, lost coverage, and stopped reporting. The note does not identify those tags or place them in the room during those intervals. Repeating the observation faithfully does not supply that missing connection.

The assessment instead separates three things:

- **Measured finding:** each tag exceeded the configured limit for time without recorded updates.
- **Technician context:** the note describes equipment movement and poor coverage in a storage room.
- **Investigation:** compare each interval with documented equipment movement and check reception in that room.

The [two-page assessment](/files/agent-evidence-checks/nursing-unit-b-assessment.pdf) demonstrates that presentation. Its measurements come from saved results. Its explanatory wording and follow-up steps are coded specifically for this zone example; they are not evidence that a model independently generated a correct investigation plan.

The current workflow retains candidate assessments without selecting a final cause or resolving conflicting notes. That preserves the distinction between a useful lead and a confirmed explanation.

## Make every check's responsibility explicit

This version follows predefined Python stages, fitting the workflow side of [Anthropic's distinction between workflows and agents](https://www.anthropic.com/engineering/building-effective-agents). Code calculates measurements and checks exact conditions. Models interpret language within those boundaries. The same evidence problem applies when an autonomous agent passes an interpretation to its next tool call or decision.

When building either kind of system, I would carry forward four practices:

- Preserve the original claim and full source beside each assessment.
- State which checks code enforces and which judgments a model proposes.
- Evaluate explanations as well as labels, including negation, missing evidence, and units.
- Give unresolved findings a useful next action without promoting a possible explanation to a confirmed cause.

A citation makes a claim traceable. The next responsibility is to show what the source actually supports and where further evidence is needed.
