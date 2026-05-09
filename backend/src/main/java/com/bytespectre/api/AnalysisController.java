package com.bytespectre.api;

import com.bytespectre.analysis.model.JarAnalysisReport;
import com.bytespectre.analysis.service.DecompileService;
import com.bytespectre.analysis.service.JarAnalysisService;
import jakarta.validation.constraints.NotBlank;
import java.io.IOException;
import java.nio.file.Path;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/analysis")
@CrossOrigin(originPatterns = {"http://localhost:*", "http://127.0.0.1:*"})
public class AnalysisController {
    private final JarAnalysisService jarAnalysisService;
    private final DecompileService decompileService;

    public AnalysisController(JarAnalysisService jarAnalysisService, DecompileService decompileService) {
        this.jarAnalysisService = jarAnalysisService;
        this.decompileService = decompileService;
    }

    @GetMapping("/health")
    public AnalysisHealth health() {
        return new AnalysisHealth("online", "static-engine-v1", "sandbox-runtime-planned");
    }

    @GetMapping("/capabilities")
    public AnalysisCapabilities capabilities() {
        return new AnalysisCapabilities(
                "static-engine-v1",
                java.util.List.of("Fabric", "Quilt", "Forge", "NeoForge", "Bukkit", "Spigot", "Paper", "Velocity", "BungeeCord", "Minecraft Client", "Java Agent", "Generic JVM"),
                java.util.List.of("fabric.mod.json", "quilt.mod.json", "mods.toml", "neoforge.mods.toml", "plugin.yml", "paper-plugin.yml", "velocity-plugin.json", "bungee.yml", "mcmod.info"),
                java.util.List.of("Bytecode", "Obfuscation", "Manifest", "Asset Packaging", "Credential Exposure", "Anti-Analysis", "Filesystem Mutation"),
                java.util.List.of("json", "markdown")
        );
    }

    @PostMapping(value = "/jar", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public JarAnalysisReport analyzeUpload(@RequestParam("file") MultipartFile file) throws IOException {
        return jarAnalysisService.analyze(file);
    }

    @PostMapping(value = "/jar/decompile", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = "application/zip")
    public ResponseEntity<byte[]> decompileUpload(
            @RequestParam("file") MultipartFile file,
            @RequestParam(name = "deobfuscate", defaultValue = "false") boolean deobfuscate
    ) throws IOException {
        java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("bytespectre-decompile-", ".jar");
        file.transferTo(tempFile);
        try {
            byte[] zip = decompileService.decompileJarToZip(tempFile, deobfuscate);
            String base = (file.getOriginalFilename() == null ? "artifact" : file.getOriginalFilename()).replaceAll("\\.jar$", "");
            String name = base + (deobfuscate ? "-deobf" : "-decompile") + ".zip";
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + name + "\"")
                    .contentType(org.springframework.http.MediaType.parseMediaType("application/zip"))
                    .body(zip);
        } finally {
            java.nio.file.Files.deleteIfExists(tempFile);
        }
    }

    @PostMapping(value = "/jar/path/decompile", produces = "application/zip")
    public ResponseEntity<byte[]> decompilePath(
            @RequestParam @NotBlank String path,
            @RequestParam(name = "deobfuscate", defaultValue = "false") boolean deobfuscate
    ) throws IOException {
        java.nio.file.Path jarPath = java.nio.file.Path.of(path);
        byte[] zip = decompileService.decompileJarToZip(jarPath, deobfuscate);
        String base = jarPath.getFileName().toString().replaceAll("\\.jar$", "");
        String name = base + (deobfuscate ? "-deobf" : "-decompile") + ".zip";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + name + "\"")
                .contentType(org.springframework.http.MediaType.parseMediaType("application/zip"))
                .body(zip);
    }

    @PostMapping("/jar/path")
    public JarAnalysisReport analyzePath(@RequestParam @NotBlank String path) throws IOException {
        return jarAnalysisService.analyze(Path.of(path));
    }

    public record AnalysisHealth(String status, String staticEngine, String runtimeSandbox) {
    }
}
