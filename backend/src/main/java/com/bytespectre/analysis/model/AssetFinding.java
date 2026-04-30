package com.bytespectre.analysis.model;

public record AssetFinding(
        String path,
        String type,
        String signal,
        String explanation
) {
}

