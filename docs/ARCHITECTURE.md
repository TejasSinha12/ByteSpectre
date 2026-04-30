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

- Decompiler adapters for CFR, FernFlower, and Procyon.
- Netty protocol tracing and packet decoder plugins.
- Java agent probes for reflection, class loading, instrumentation, native loading, and process spawning.
- Signature marketplace and threat intelligence feeds.
- Distributed scan workers and cloud sandbox orchestration.
- Graph database export for large-scale relationship querying.

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
- Minecraft Forge or NeoForge-style mod.
- Bukkit, Spigot, Paper server plugin.
- Velocity and BungeeCord proxy plugin.
- Minecraft client-side JAR.
- Java agent.
- Generic executable Java application or library.

This taxonomy should grow independently from suspicious behavior detectors. A plugin or mod can be perfectly benign, while malware-like behavior can appear in any family.
