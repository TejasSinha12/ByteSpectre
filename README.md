# ByteSpectre

ByteSpectre is an AI-ready JVM security and reverse engineering platform for analyzing Java applications, Minecraft clients, mods, plugins, and obfuscated JARs.

The repository is organized as a scalable platform rather than a single-purpose utility:

- `backend/` - Spring Boot API and static JAR analysis engine.
- `frontend/` - React/Vite security workbench UI.
- `ai-service/` - Python boundary for classification and anomaly scoring.
- `sandbox-agent/` - Java agent scaffold for runtime sandbox telemetry.
- `docs/` - Architecture and expansion notes.
- `docker-compose.yml` - PostgreSQL and Redis services for the planned analysis pipeline.

## Current Vertical Slice

The first implementation delivers a runnable foundation:

- Upload or reference a JAR for static analysis.
- Parse JAR metadata, manifests, class counts, package inventory, resources, and translation/assets.
- Inspect bytecode with ASM for reflection, classloader usage, networking, instrumentation, native calls, packet/client hints, inheritance, and method-call edges.
- Produce risk scoring, suspicious indicators, behavior categories, and explanation text.
- Extract plugin/mod descriptors (Fabric/Quilt/Forge/NeoForge, Bukkit/Paper, Velocity/Bungee) and surface key fields.
- Extract plugin/mod channels when detectable from bytecode callsites (Bukkit/Fabric patterns) and fallback raw scans for channel-like identifiers in packed/unreadable artifacts.
- Decompile JARs to a downloadable source ZIP (CFR) with an optional deobfuscation mode that enables CFR anti-obfuscation and rename/recovery options for better readability.
- Render an enterprise-style analysis dashboard with live event feed, risk breakdown, asset intelligence, and graph-oriented data panels.

## Run

Backend:

```bash
cd backend
mvn spring-boot:run
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Services:

```bash
docker compose up -d
```

AI service:

```bash
cd ai-service
uvicorn app.main:app --reload --port 8090
```

Sandbox agent:

```bash
cd sandbox-agent
mvn package
java -javaagent:target/bytespectre-sandbox-agent-0.1.0-SNAPSHOT.jar -jar /path/to/sample.jar
```

The frontend expects the backend at `http://localhost:8080`.

## Decompile / Export

From the UI:

- Use `JSON` / `Markdown` to export reports.
- Use `Decompile ZIP` to download decompiled sources as a ZIP.
- Use `Deobfuscate ZIP` for CFR anti-obfuscation and rename/recovery options (readability improvement, not original-name recovery).

API:

- `POST /api/analysis/jar/decompile?deobfuscate=false|true` (multipart upload, returns ZIP)
- `POST /api/analysis/jar/path/decompile?path=/abs/file.jar&deobfuscate=false|true` (returns ZIP)

## Channel Detection Notes

- Channel results are static-analysis evidence and can include fallback candidates from raw bytes when classes are unreadable.
- Entries shaped like `namespace:path` are stronger signals; obfuscated/runtime-built channels may still be missed.
- Runtime-only registration can require sandbox/runtime tracing for exact channel enumeration.
