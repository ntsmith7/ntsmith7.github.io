---
title: "A Citation Isn't Proof: Building Evidence Checks into AI Workflows"
date: 2026-10-20
draft: false
tags: ["AI", "Agents", "Evaluation", "RTLS"]
summary: "A valid citation can still support a bad conclusion. Lessons from building an RTLS assessment workflow: separate source checks, claim support, and relevance, then evaluate the explanations as well as the labels."
description: "How to separate source validation, claim support, and relevance in AI workflows, illustrated with a synthetic RTLS assessment and saved evaluation results."
---

Two equipment tags each have a five-hour interval without recorded updates. A technician's note says staff move equipment into a utility room with poor wireless coverage. It is easy to connect those observations: the equipment went into the room, lost coverage, and stopped reporting.

That explanation has a source. It also contains a step the source never established: that these particular tags were in that room during those intervals.

This is the problem I have been working through in the second version of my [Deployment Readiness Agent](/projects/deployment-readiness-agent/). The project uses real-time location system (RTLS) measurements and technician notes to prepare a site assessment. All examples here use fictional facilities, synthetic telemetry, and synthetic notes. They demonstrate the workflow's behavior, not results from a hospital deployment.

The broader question is useful for anyone building agents that interpret records: **what does each validation check actually establish about the answer?**

## Four questions behind a cited claim

A schema can require a claim, a source ID, and a quotation. Those fields make the result easier to process and inspect. Their presence does not establish that the claim follows from the source.

I found it useful to separate four questions:

1. **Structure:** Does the response have the required fields and allowed values?
2. **Source integrity and scope:** Does the note exist, does the quotation occur in it, and does its declared site, tag, or zone scope apply?
3. **Claim support:** Does the full note support the proposed claim as written, including its level of certainty?
4. **Relevance:** Does that same claim concern the measured problem being assessed?

The first two lend themselves to code. The last two require interpreting meaning. In this project, an LLM makes those judgments, so they remain subject to evaluation and review.

One evaluation case makes the limit of quotation matching clear. The note says:

> For MRW-TAG-0031, we ruled out the hypothesis that rack shielding caused the weak signal. The cause remains unknown.

The phrase “rack shielding caused the weak signal” is an exact substring. Extracted on its own, it supports the opposite impression from the full sentence. A string comparison can confirm the quotation exists. The support assessment has to account for “ruled out.”

## Support and relevance are different judgments

Suppose the proposed claim is that an access-point power outage caused a reporting gap. That claim is relevant to missing updates. If its cited note only discusses shielding near the tag, the note does not support the outage claim.

The reverse is possible too. A note may explicitly say a loose caster caused a cart to wobble. The claim is supported by the note, but it provides no identified explanation for weak radio reception. Sharing an equipment tag does not make every observation about that equipment relevant to every problem.

In the current implementation, I assess these questions in separate model requests:

- The **support request** receives the unchanged claim, its quotation, and the full source note.
- The **relevance request** receives the unchanged claim and the measured violation, including units.

Neither receives the other's answer or conversation history. This limits the context each judgment can use. It also makes failures easier to inspect: did the model misread the note, or misjudge the relationship to the measurement?

The separation costs another model call. It also leaves both stages capable of error. Its value is a clearer responsibility for each stage and a more precise way to evaluate the results.

## Design the workflow around those responsibilities

[Anthropic's description of workflows and agents](https://www.anthropic.com/engineering/building-effective-agents) distinguishes predefined execution paths from systems where a model directs its own process and tool use. Under that distinction, this version of my project is a constrained workflow. Python determines the stages; the model performs specific language tasks within them.

Python loads the measurements, calculates per-tag statistics, and compares them with configured thresholds. It also checks source IDs, declared scope, and exact quotations. The model extracts information from freeform notes and assesses eligible claims. Saved results retain the inputs, judgments, unresolved notes, and rejected candidates.

These boundaries matter because an agent's intermediate output can become the next stage's input. If an extracted possibility becomes a confirmed fact, later stages may carry that stronger claim forward. Keeping the original note beside the extracted claim makes that change inspectable.

The retry policy follows the same distinction. Malformed assessment output gets one retry. A valid “unsupported” or “uncertain” judgment is retained. Asking again until a positive answer appears would change what the workflow is measuring.

## A perfect label score can hide a bad explanation

One saved evaluation batch ran nine authored cases three times each. All **27 assessments matched both expected labels**: claim support and relevance. There were no request errors.

The explanations still contained mistakes.

In a maintenance case, the note said “No AP maintenance was recorded.” The proposed claim was that a maintenance shutdown caused the reporting gap. The model correctly labeled the claim unsupported, but explained that the absence of a maintenance record contradicted the claim.

Those are different statements. Missing documentation leaves the event unestablished. It does not establish that the event did not happen.

Another explanation in that batch described a 300-minute gap against a 15-minute limit as “a 300s gap against a 15s threshold.” The labels were still correct. The explanation changed the units.

This is why I now distinguish several kinds of checks. Code tests verify mechanics such as request contents, validation, and error handling. Semantic evaluations compare model judgments with authored expectations. Explanation review checks whether the text preserves the source's meaning and the measurement's units.

Following those findings, I added explicit units to relevance inputs and a required support reason, such as missing evidence, contradiction, or overstated certainty. The schema enforces valid label/reason combinations. The model still has to choose the right reason, and the explanation still needs review.

These results come from a small synthetic case set with repeated runs, not 27 independent deployment scenarios. They do not establish general accuracy. They do show a specific failure of the earlier scoring approach: label agreement alone missed errors that mattered to the reader.

The [saved evaluation evidence](/files/agent-evidence-checks/evaluation-evidence.json) includes the six run summaries, all 27 case results, and the source metadata for that batch.

## Give missing evidence a useful outcome

Return to the utility-room example. In the synthetic NursingUnit-B assessment, two tags each had a longest interval without recorded updates of five hours, against a configured limit of 15 minutes. Another tag was received by a median of one access point, against the configured requirement of three. These limits belong to this proof of concept.

The technician note describes equipment movement into a room with poor access-point coverage. Its declared scope is NursingUnit-B. That makes it eligible context for the zone, but the note names none of the affected tags and does not place them in the room during their measured failures.

A claim that accurately repeats that observation can be supported by the note and relevant to the investigation. The missing connection to the individual tags remains missing.

The assessment can still provide a useful next step: identify each missing-update interval, compare it with documented equipment movement, measure reception in the utility room, and retest against the configured limits after any verified corrective action.

The current workflow preserves candidate assessments without selecting a final cause. It also does not resolve conflicting notes. That keeps the distinction between an investigative lead and a confirmed explanation visible to the engineer.

## Keep the evidence boundary visible in the report

These distinctions need to survive the final presentation. A stakeholder should be able to tell what was measured, what a technician reported, and what still needs investigation.

In the revised zone section, “max gap: 300” becomes “five hours without recorded updates.” The engine's confidence score stays in supporting measurements, with an explicit explanation that it is not measured physical location accuracy. The main narrative describes the issue and the follow-up it warrants.

The [two-page NursingUnit-B assessment](/files/agent-evidence-checks/nursing-unit-b-assessment.pdf) shows that separation. It is the first revised zone section. The PDF is rendered by deterministic code from saved review results; it is not a new model-generated diagnosis, and rendering does not independently validate model explanations.

A dependable workflow needs a useful response when the evidence ends. For this project, that response is a measured finding, the relevant source context, a clear unresolved question, and a way for an engineer to investigate it. Every additional conclusion has to earn its place through evidence.
