# ByteSpectre AI Service

This service is the placeholder boundary for the AI-assisted detection layer. The current implementation exposes a deterministic bootstrap classifier so the rest of the platform can integrate against a stable API before trained models are introduced.

Run:

```bash
uvicorn app.main:app --reload --port 8090
```

Planned model tracks:

- Static feature vector anomaly detection.
- Embedding similarity for related JAR families.
- Malware probability classification.
- Cheat-client capability classification.
- Explanation generation from indicator evidence.

