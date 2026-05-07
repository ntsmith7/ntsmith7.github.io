---
title: "A Live Detection Engineering Lab"
date: 2026-05-07
tags: ["Kubernetes", "Detection Engineering", "Elasticsearch", "Go", "OWASP Juice Shop", "MITRE ATT&CK"]
summary: "A detection pipeline running against an isolated lab of OWASP Juice Shop. Real attack telemetry, classified against MITRE ATT&CK, streamed live to this page."
---

{{< live-security-lab >}}

## Why I built this

I built this to learn detection engineering. The lab gives me somewhere to attack a real application, write detection rules against the resulting logs, and watch them fire or miss.

The pipeline has the same shape as a production detection system. Logs are collected, normalized, matched against detection rules, and surfaced. A real one ingests millions of events per day from many source types, uses a mature rule engine such as Sigma or Elastic Detection Rules with backtesting and suppression, integrates with analyst workflows and alert lifecycle tooling, and has tiered storage and on-call coverage. This lab has one application, one log shape, a hardcoded set of regex rules I wrote in Go, and a live tail. The simplifications are intentional. Removing the production scaffolding makes the mechanics directly inspectable, which is what makes it useful for learning.

The widget above is connected to the lab in real time. Each event in the feed started as an HTTP request to OWASP Juice Shop inside an isolated local cluster, was shipped through the log pipeline, and was classified by the detection layer. A `T1190` tag indicates the detection layer matched a SQL injection pattern in a request that just happened.

## Design constraints

The lab needed to satisfy three constraints simultaneously.

It had to use real telemetry. Synthetic logs do not teach the patterns that show up in real traffic, including the noise. The lab needed a real application generating its own logs from real HTTP requests, so that detection rules would match against payloads with the same shape as production data.

It had to be isolated. A deliberately vulnerable application has known exploitable paths and should not be reachable from the public internet under any circumstances. The lab itself had to remain inside an environment that could not receive inbound traffic from outside.

It had to be observable to a remote reader. The public visibility goal required that the live state of the lab be available to anyone reading this page, in real time, without exposing the lab itself.

These three constraints are mutually satisfiable only if the data path is one-directional.

## Architecture

OWASP Juice Shop runs in a local kind cluster behind an Nginx reverse proxy. The proxy exists to log request bodies and query strings in a format the detection layer can match against; Juice Shop's own application logs do not include the raw HTTP payloads. Filebeat tails the container logs and ships them to an Elasticsearch instance running in the same cluster. None of these components have ingress from outside the local environment.

Outbound connectivity to the public internet is handled by a Go service that polls Elasticsearch using `search_after` cursors, batches new documents, and pushes them to a separate enrichment service running in Azure Container Apps. The push is one-way and authenticated with a shared token. The exporter has no inbound listener, and the enrichment service has no path back into the cluster.

The enrichment service performs two functions. It tags each event against a set of MITRE ATT&CK regex rules (`union select` matches T1190, `<script` matches T1059.007), and it broadcasts tagged events to clients connected to its `/stream` endpoint over Server-Sent Events. The endpoint is read-only.

This produces a one-directional data path. Events flow outward from the cluster, through the exporter, through the enrichment service, and to any reader. No path exists in the reverse direction.

## Public surface hardening

The asymmetric data path addresses the architectural exposure. The enrichment service itself is internet-reachable and required additional measures.

The `/ingest` endpoint requires a shared token. The service refuses to start if the token is unset or set to a known placeholder value; an earlier version logged a warning and continued, which would have allowed the service to ship with an unauthenticated ingest endpoint. The startup check converts a silent failure mode into a loud one.

Token comparison uses `crypto/subtle.ConstantTimeCompare`. With a single rarely-rotated token, a timing-side-channel attack against the comparison is theoretical. The constant-time comparison eliminates the class of issue at negligible cost.

Credentials are redacted before broadcast. The Nginx access logs include request bodies, which means failed login attempts include passwords and other credential-shaped data. A set of regular expressions in the enrichment service replaces the values of common secret fields (`password`, `token`, `Authorization`, cookie values) with `[REDACTED]` before the event is written to the public stream. Detection rules run against the pre-redaction text, so MITRE tagging is unaffected by the redaction.

The full source document is not included in broadcast events. An earlier version of the enrichment service emitted the entire Elasticsearch document as a `raw` field on each event, which would have leaked Filebeat metadata, host names, file paths, and any other contents of `_source`. The public event payload now contains only the fields the page consumes: id, timestamp, redacted message, stream name, and MITRE tags.

These are standard measures for an internet-facing service. They are documented here because the service is internet-facing.

## Issues encountered during development

Three bugs from the build are worth recording.

**Elasticsearch 8 disables `fielddata` on `_id` by default.** The exporter's `search_after` pagination used `_id` as a tiebreaker for sorting after the timestamp, which produced an `illegal_argument_exception` from every query. Switching the tiebreaker to `_seq_no` resolves the issue. `_seq_no` is sortable, monotonic per shard, and supported across the version range.

**Filebeat's autodiscover provider does not work reliably on a kind cluster.** With autodiscover enabled, Filebeat reported normal metrics but ran zero harvesters. The Kubernetes metadata matcher could not resolve the symlink chain that kind uses for container log files. Replacing autodiscover with a plain filestream input pointing at `/var/log/containers/<workload>-*.log` produced reliable log shipping at the cost of pod metadata enrichment, which the rest of the pipeline does not consume.

**Elasticsearch returns sort values as typed JSON, not strings.** The `@timestamp` field is returned as a `float64` of epoch milliseconds. Formatting it with `fmt.Sprintf("%v", ...)` produces scientific notation, which then fails to round-trip through the next `search_after` query. The exporter now type-switches on the sort value and formats integers and floats explicitly.

## Planned extensions

The current pipeline handles application-layer telemetry from a single source. Several extensions are planned.

A Falco deployment in the cluster would add syscall-level detections for container-internal activity. A second exporter would forward Falco events through the same enrichment service and rule engine. A scheduled traffic generator would maintain a baseline level of activity in the feed independent of manual interaction. A small aggregation view on this page would group events by detection ID and display rolling counts, replacing the flat tail with something closer to a SIEM dashboard.

Each of these is an additional use case for the same underlying pipeline. The core architecture is intended to remain stable as the lab grows.
