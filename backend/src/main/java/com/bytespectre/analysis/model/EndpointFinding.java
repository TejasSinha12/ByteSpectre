package com.bytespectre.analysis.model;

public record EndpointFinding(
        String kind,
        String value,
        String evidence,
        int confidence
) {
}

