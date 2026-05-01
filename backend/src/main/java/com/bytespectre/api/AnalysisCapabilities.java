package com.bytespectre.api;

import java.util.List;

public record AnalysisCapabilities(
        String staticEngineVersion,
        List<String> artifactFamilies,
        List<String> descriptorFormats,
        List<String> detectorFamilies,
        List<String> exportFormats
) {
}

