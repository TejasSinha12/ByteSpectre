package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.model.Indicator;
import java.util.List;

class ManifestDetector implements JarDetector {
    @Override
    public List<Indicator> detect(AnalysisContext context) {
        if (context.manifest().keySet().stream().anyMatch(key -> key.equalsIgnoreCase("Premain-Class") || key.equalsIgnoreCase("Agent-Class"))) {
            return List.of(new Indicator("manifest.agent", "Java agent entrypoint", "Runtime Instrumentation", 8, 96, context.manifest().toString(), "The manifest declares Java agent entrypoints that can instrument other JVM code."));
        }
        return List.of();
    }
}

