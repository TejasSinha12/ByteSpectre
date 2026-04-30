from __future__ import annotations

from typing import Any

import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel, Field


app = FastAPI(title="ByteSpectre AI Service", version="0.1.0")


class StaticFeatureVector(BaseModel):
    class_count: int = Field(default=0, alias="classCount")
    method_count: int = Field(default=0, alias="methodCount")
    indicator_count: int = Field(default=0, alias="indicatorCount")
    asset_finding_count: int = Field(default=0, alias="assetFindingCount")
    reflection_class_ratio: float = Field(default=0, alias="reflectionClassRatio")
    network_class_ratio: float = Field(default=0, alias="networkClassRatio")
    classloader_class_ratio: float = Field(default=0, alias="classloaderClassRatio")
    packet_signal_ratio: float = Field(default=0, alias="packetSignalRatio")
    model_config = {"populate_by_name": True}


class ClassificationRequest(BaseModel):
    analysis_id: str = Field(alias="analysisId")
    file_name: str = Field(alias="fileName")
    static_features: StaticFeatureVector = Field(alias="staticFeatures")
    indicators: list[dict[str, Any]] = []


class ClassificationResponse(BaseModel):
    analysis_id: str = Field(alias="analysisId")
    malware_probability: float = Field(alias="malwareProbability")
    cheat_client_probability: float = Field(alias="cheatClientProbability")
    anomaly_score: float = Field(alias="anomalyScore")
    explanation: list[str]
    model_version: str = Field(default="heuristic-bootstrap-v1", alias="modelVersion")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "online", "modelVersion": "heuristic-bootstrap-v1"}


@app.post("/classify", response_model=ClassificationResponse)
def classify(request: ClassificationRequest) -> ClassificationResponse:
    features = request.static_features
    vector = np.array(
        [
            min(features.indicator_count / 12, 1),
            features.reflection_class_ratio,
            features.network_class_ratio,
            features.classloader_class_ratio,
            features.packet_signal_ratio,
            min(features.asset_finding_count / 8, 1),
        ],
        dtype=float,
    )

    malware_probability = float(np.clip(vector @ np.array([0.24, 0.12, 0.18, 0.24, 0.08, 0.14]), 0, 1))
    cheat_client_probability = float(np.clip(vector @ np.array([0.14, 0.12, 0.08, 0.08, 0.36, 0.22]), 0, 1))
    anomaly_score = float(np.clip(np.linalg.norm(vector) / np.sqrt(len(vector)), 0, 1))

    explanation = []
    if features.classloader_class_ratio > 0:
        explanation.append("Dynamic class loading contributes to malware and hidden functionality probability.")
    if features.packet_signal_ratio > 0:
        explanation.append("Packet and protocol signals increase cheat-client and network manipulation probability.")
    if features.asset_finding_count:
        explanation.append("Asset and translation vocabulary indicates user-facing capability metadata.")
    if not explanation:
        explanation.append("No dominant AI signal was present in the bootstrap feature vector.")

    return ClassificationResponse(
        analysisId=request.analysis_id,
        malwareProbability=round(malware_probability, 3),
        cheatClientProbability=round(cheat_client_probability, 3),
        anomalyScore=round(anomaly_score, 3),
        explanation=explanation,
    )

