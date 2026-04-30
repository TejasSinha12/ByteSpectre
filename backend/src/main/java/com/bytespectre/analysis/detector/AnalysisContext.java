package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.bytecode.ClassBytecodeFacts;
import com.bytespectre.analysis.model.AssetFinding;
import java.util.List;
import java.util.Map;

public record AnalysisContext(
        List<ClassBytecodeFacts> classFacts,
        List<AssetFinding> assetFindings,
        List<String> jarEntryNames,
        Map<String, String> manifest
) {
}

