package com.bytespectre.analysis.model;

public record DependencyArtifact(
        String path,
        String name,
        String version,
        long sizeBytes,
        String source
) {
}

