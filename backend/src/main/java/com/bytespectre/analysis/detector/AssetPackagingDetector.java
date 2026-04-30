package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.model.Indicator;
import java.util.ArrayList;
import java.util.List;

class AssetPackagingDetector implements JarDetector {
    @Override
    public List<Indicator> detect(AnalysisContext context) {
        List<Indicator> indicators = new ArrayList<>();

        long nativeAssets = context.assetFindings().stream().filter(asset -> asset.type().equals("native")).count();
        if (nativeAssets > 0) {
            indicators.add(new Indicator("assets.native", "Native binary resources", "Native Boundary", 6, 90, nativeAssets + " native resources", "Bundled native code should be reviewed and sandboxed before execution."));
        }

        long nestedJars = context.jarEntryNames().stream().filter(name -> name.endsWith(".jar")).count();
        if (nestedJars > 0) {
            indicators.add(new Indicator("resources.nested-jars", "Nested JAR payloads", "Packaging", 5, 86, nestedJars + " nested JAR resources", "Nested archives can carry staged dependencies or hidden payloads."));
        }

        return indicators;
    }
}

