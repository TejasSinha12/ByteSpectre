package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.model.Indicator;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class DetectorRegistry {
    private final List<JarDetector> detectors;

    public DetectorRegistry() {
        this.detectors = List.of(
                new AggregateBytecodeDetector(),
                new ObfuscationDetector(),
                new ManifestDetector(),
                new AssetPackagingDetector(),
                new SecretStringDetector(),
                new EnvironmentAccessDetector(),
                new FileSystemMutationDetector()
        );
    }

    public List<Indicator> detect(AnalysisContext context) {
        List<Indicator> indicators = new ArrayList<>();
        for (JarDetector detector : detectors) {
            indicators.addAll(detector.detect(context));
        }
        return indicators;
    }
}
