package com.bytespectre.analysis.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record JarAnalysisReport(
        String analysisId,
        String fileName,
        long fileSizeBytes,
        Instant analyzedAt,
        RiskLevel riskLevel,
        int riskScore,
        String summary,
        Map<String, String> manifest,
        List<String> behaviorCategories,
        List<ArtifactClassification> artifactClassifications,
        List<Indicator> indicators,
        List<PackageSummary> packages,
        List<ClassRelationship> relationships,
        List<MethodCallEdge> methodCallEdges,
        List<AssetFinding> assetFindings,
        Map<String, Long> resourceSummary,
        Map<String, Object> aiSignals
) {
}
