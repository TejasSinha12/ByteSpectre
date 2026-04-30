package com.bytespectre.analysis.model;

public record Indicator(
        String id,
        String title,
        String category,
        int severity,
        int confidence,
        String evidence,
        String explanation
) {
}
