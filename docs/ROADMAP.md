# ByteSpectre Development Roadmap

This roadmap is optimized for daily small commits while still moving the platform toward a serious JVM security workbench.

## Near Term

- Add detector fixtures for each suspicious behavior family.
- Persist analysis reports in PostgreSQL.
- Add artifact history and comparison views.
- Convert the graph preview into a filterable graph workspace.
- Stream sandbox agent events into the backend over WebSocket.
- Add signed report bundles with SHA-256 identity, detector versions, and reproducible scan settings.
- Promote backend capabilities metadata into versioned API contracts.

## Middle Term

- Add FernFlower/Procyon decompiler adapters and CFR mapping-based deobfuscation (`obfuscationpath` support).
- Add deeper Fabric, Forge, NeoForge, Quilt, Paper, Velocity, and Bungee descriptor parsing.
- Add packet, Netty pipeline, and protocol decoder detectors.
- Feed static vectors into the AI service and store model outputs.

## Longer Term

- Distributed scan workers.
- Collaborative investigations.
- Signature packs and threat intelligence feeds.
- Cloud sandbox orchestration.
- JVM memory forensics and process injection telemetry.
