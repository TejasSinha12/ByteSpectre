package com.bytespectre.analysis.model;

public record Indicator(
        String id,
        String title,
        String category,
        int severity,
        String evidence,
        String explanation
) {
}

