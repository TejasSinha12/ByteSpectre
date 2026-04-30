package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.model.Indicator;
import java.util.List;

public interface JarDetector {
    List<Indicator> detect(AnalysisContext context);
}

