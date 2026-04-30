package com.bytespectre.analysis.model;

import java.util.Map;

public record DescriptorMetadata(
        String path,
        String type,
        Map<String, String> fields
) {
}

