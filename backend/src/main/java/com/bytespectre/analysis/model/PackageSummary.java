package com.bytespectre.analysis.model;

public record PackageSummary(
        String name,
        int classCount,
        int suspiciousSignalCount
) {
}

