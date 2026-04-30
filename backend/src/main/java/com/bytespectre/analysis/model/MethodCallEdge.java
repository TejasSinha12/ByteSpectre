package com.bytespectre.analysis.model;

public record MethodCallEdge(
        String sourceClass,
        String sourceMethod,
        String targetOwner,
        String targetMethod,
        String descriptor
) {
}

