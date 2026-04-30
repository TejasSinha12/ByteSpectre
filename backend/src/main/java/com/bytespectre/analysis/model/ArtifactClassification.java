package com.bytespectre.analysis.model;

import java.util.List;

public record ArtifactClassification(
        String id,
        String label,
        String family,
        int confidence,
        List<String> evidence,
        String explanation
) {
}

