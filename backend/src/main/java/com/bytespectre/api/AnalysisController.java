package com.bytespectre.api;

import com.bytespectre.analysis.model.JarAnalysisReport;
import com.bytespectre.analysis.service.JarAnalysisService;
import jakarta.validation.constraints.NotBlank;
import java.io.IOException;
import java.nio.file.Path;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/analysis")
@CrossOrigin(origins = {"http://localhost:5173", "http://127.0.0.1:5173"})
public class AnalysisController {
    private final JarAnalysisService jarAnalysisService;

    public AnalysisController(JarAnalysisService jarAnalysisService) {
        this.jarAnalysisService = jarAnalysisService;
    }

    @GetMapping("/health")
    public AnalysisHealth health() {
        return new AnalysisHealth("online", "static-engine-v1", "sandbox-runtime-planned");
    }

    @PostMapping(value = "/jar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public JarAnalysisReport analyzeUpload(@RequestParam("file") MultipartFile file) throws IOException {
        return jarAnalysisService.analyze(file);
    }

    @PostMapping("/jar/path")
    public JarAnalysisReport analyzePath(@RequestParam @NotBlank String path) throws IOException {
        return jarAnalysisService.analyze(Path.of(path));
    }

    public record AnalysisHealth(String status, String staticEngine, String runtimeSandbox) {
    }
}

