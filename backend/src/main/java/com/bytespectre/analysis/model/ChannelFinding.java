package com.bytespectre.analysis.model;

public record ChannelFinding(
        String system,
        String direction,
        String channel,
        String sourceClass,
        String sourceMethod
) {
}

