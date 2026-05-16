# ByteSpectre Architecture

ByteSpectre is organized around an event-driven JVM analysis pipeline.

## Platform Boundaries

- **Static Analysis API**: Spring Boot service that parses JAR files, extracts manifests/resources, inspects bytecode with ASM, and emits graph-ready evidence.
- **Runtime Sandbox**: Planned JVM agent and isolated process runner for tracing threads, reflection, instrumentation, packet flow, native loading, process execution, and network activity.
- **AI Service**: Python service boundary for anomaly detection, malware probability, cheat-client capability inference, clustering, and explainable scoring.
- **Workbench UI**: React console for artifact submission, triage, graph exploration, AI signals, asset intelligence, and realtime event feeds.
- **Storage Layer**: PostgreSQL for durable analysis records and Redis for event/cache workloads.

## Analysis Flow

1. An artifact is uploaded or referenced by absolute path.
2. Static analysis extracts bytecode facts, resource summaries, manifest values, asset signals, method-call edges, and inheritance relationships.
3. Risk scoring converts evidence into indicator explanations and normalized AI feature vectors.
4. The UI renders the report immediately while future workers persist it and dispatch AI/sandbox jobs.
5. Runtime analysis and AI classification publish events over WebSocket topics for live inspection.

## Expansion Points

- Decompiler adapters for FernFlower and Procyon, plus deeper CFR mapping support.
- Netty protocol tracing and packet decoder plugins.
- Java agent probes for reflection, class loading, instrumentation, native loading, and process spawning.
- Signature marketplace and threat intelligence feeds.
- Distributed scan workers and cloud sandbox orchestration.
- Graph database export for large-scale relationship querying.

## Runtime Sandbox Agent

The `sandbox-agent/` module is the first runtime analysis boundary. It builds a Java agent with `Premain-Class` and `Agent-Class` manifest entries, installs a class-load transformer, and emits structured sandbox events to stdout.

Current telemetry:

- Agent install and shutdown events.
- Interesting class loads for reflection, instrumentation, networking, Netty, ASM, Mixin, Minecraft, Bukkit, Fabric, and Forge namespaces.

Near-term expansion:

- Socket connect tracing.
- Reflection invocation tracing.
- Thread creation tracing.
- Process execution interception.
- WebSocket streaming back to the Spring Boot API.

## Detector Architecture

Static detection rules live behind the `JarDetector` interface. Each detector receives an `AnalysisContext` containing class bytecode facts, asset findings, JAR entry names, and manifest attributes, then returns explainable `Indicator` records.

Current detector families:

- `AggregateBytecodeDetector` for reflection, classloader, instrumentation, network, native, process, packet, and mixin signals.
- `ObfuscationDetector` for short-name and encoded-string clusters.
- `ManifestDetector` for Java agent entrypoints.
- `AssetPackagingDetector` for native binaries and nested JAR payloads.

Daily detector work should follow this pattern:

1. Add or update a focused detector.
2. Register it in `DetectorRegistry`.
3. Add a fixture-driven unit test.
4. Surface any new indicator fields in the UI.
5. Document the detector behavior and confidence assumptions.

## Artifact Classification

Artifact classification runs before risk interpretation and answers a different question: what kind of JAR is this? The classifier emits `ArtifactClassification` records with label, family, confidence, evidence, and explanation.

Current families:

- Minecraft Fabric mod.
- Minecraft Quilt mod.
- Minecraft Forge or NeoForge-style mod.
- Bukkit, Spigot, Paper server plugin.
- Velocity and BungeeCord proxy plugin.
- Minecraft client-side JAR.
- Java agent.
- Generic executable Java application or library.

This taxonomy should grow independently from suspicious behavior detectors. A plugin or mod can be perfectly benign, while malware-like behavior can appear in any family.

Descriptor metadata is extracted separately from classification. Known descriptor formats such as `fabric.mod.json`, `quilt.mod.json`, `mods.toml`, `plugin.yml`, `paper-plugin.yml`, `velocity-plugin.json`, and `bungee.yml` are parsed into compact key/value fields for UI inspection and future AI feature enrichment.

## Artifact Identity

Every static report includes the file name, size, and SHA-256 digest of the analyzed JAR. The digest is used by the workbench to deduplicate local history entries and should become the stable join key for persisted reports, sandbox runs, AI classifications, and future threat-intelligence lookups.

## Decompile & Deobfuscate

ByteSpectre exposes CFR-based source export endpoints that return a ZIP archive of decompiled sources. The optional "deobfuscate" mode enables CFR anti-obfuscation and rename/recovery options (`rename`, `antiobf`, illegal/small-member renaming, aggressive topsort/recover) to improve readability. It still cannot recover original symbols without a mapping file (CFR supports mappings via `obfuscationpath`, which can be integrated later).

## Channel Surface

For Minecraft plugins and mods, ByteSpectre attempts to surface "channel" usage from static artifacts.

Current extraction layers:

- Bytecode callsite extraction for Bukkit plugin messaging (`registerIncomingPluginChannel` / `registerOutgoingPluginChannel`) and Fabric-style networking registration methods.
- Identifier/ResourceLocation construction heuristics (for example `Identifier.of(namespace, path)`, `new Identifier(namespace, path)`, `new ResourceLocation(namespace, path)`), including static-field harvesting from `<clinit>` for common mod patterns.
- Fallback raw-byte scans across class/resource entries for channel-like identifiers when classes are unreadable, packed, or malformed.

Important limitations:

- Static extraction can still miss runtime-built/encrypted channel identifiers.
- Raw-byte fallback findings are lower-confidence and can include non-protocol strings that happen to match `namespace:path` patterns.

## Generic JVM Threat Surface

ByteSpectre also reports non-domain-specific (non-Minecraft) signals intended for general Java reverse engineering and malware triage:

- Hardcoded endpoints extracted from string constants (URLs, IPv4s, Discord webhooks, large base64-like blobs).
- Embedded dependency fingerprints extracted from `BOOT-INF/lib` / `WEB-INF/lib` entries and `META-INF/maven/**/pom.properties`.

These findings are surfaced as both UI panels (Threat tab) and, where applicable, severity-weighted indicators (Networking / Bytecode categories).
