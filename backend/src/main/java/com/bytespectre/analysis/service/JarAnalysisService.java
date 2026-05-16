package com.bytespectre.analysis.service;

import com.bytespectre.analysis.bytecode.BytecodeFactExtractor;
import com.bytespectre.analysis.bytecode.ClassBytecodeFacts;
import com.bytespectre.analysis.detector.AnalysisContext;
import com.bytespectre.analysis.detector.DetectorRegistry;
import com.bytespectre.analysis.model.ArtifactClassification;
import com.bytespectre.analysis.model.AssetFinding;
import com.bytespectre.analysis.model.ClassRelationship;
import com.bytespectre.analysis.model.ChannelFinding;
import com.bytespectre.analysis.model.DescriptorMetadata;
import com.bytespectre.analysis.model.DependencyArtifact;
import com.bytespectre.analysis.model.EndpointFinding;
import com.bytespectre.analysis.model.Indicator;
import com.bytespectre.analysis.model.JarAnalysisReport;
import com.bytespectre.analysis.model.MethodCallEdge;
import com.bytespectre.analysis.model.PackageSummary;
import com.bytespectre.analysis.model.RiskLevel;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.function.Predicate;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class JarAnalysisService {
    private static final int MAX_CLASS_BYTES = 12 * 1024 * 1024;
    private static final int RAW_SCAN_LIMIT = 2 * 1024 * 1024;
    private final BytecodeFactExtractor extractor = new BytecodeFactExtractor();
    private final DetectorRegistry detectorRegistry;
    private final ArtifactClassifier artifactClassifier;
    private final DescriptorMetadataExtractor descriptorMetadataExtractor;

    public JarAnalysisService(DetectorRegistry detectorRegistry, ArtifactClassifier artifactClassifier, DescriptorMetadataExtractor descriptorMetadataExtractor) {
        this.detectorRegistry = detectorRegistry;
        this.artifactClassifier = artifactClassifier;
        this.descriptorMetadataExtractor = descriptorMetadataExtractor;
    }

    public JarAnalysisReport analyze(MultipartFile upload) throws IOException {
        Path tempFile = Files.createTempFile("bytespectre-upload-", ".jar");
        upload.transferTo(tempFile);
        try {
            String fileName = upload.getOriginalFilename() == null ? tempFile.getFileName().toString() : upload.getOriginalFilename();
            return analyze(tempFile, fileName);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    public JarAnalysisReport analyze(Path jarPath) throws IOException {
        return analyze(jarPath, jarPath.getFileName().toString());
    }

    private JarAnalysisReport analyze(Path jarPath, String fileName) throws IOException {
        if (!Files.isRegularFile(jarPath)) {
            throw new IOException("JAR path does not point to a file: " + jarPath);
        }
        if (!fileName.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            throw new IOException("Only .jar artifacts are supported by the current static analyzer.");
        }

        List<ClassBytecodeFacts> classFacts = new ArrayList<>();
        List<AssetFinding> assetFindings = new ArrayList<>();
        Map<String, Long> resourceSummary = new LinkedHashMap<>();
        Map<String, String> manifest = new LinkedHashMap<>();
        List<String> jarEntryNames = new ArrayList<>();
        List<DescriptorMetadata> descriptorMetadata = new ArrayList<>();
        List<ChannelFinding> fallbackChannelFindings = new ArrayList<>();

        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Manifest jarManifest = jar.getManifest();
            if (jarManifest != null) {
                jarManifest.getMainAttributes().forEach((key, value) -> manifest.put(String.valueOf(key), String.valueOf(value)));
            }

            List<JarEntry> entries = jar.stream().filter(entry -> !entry.isDirectory()).toList();
            for (JarEntry entry : entries) {
                jarEntryNames.add(entry.getName());
                classifyResource(resourceSummary, entry.getName());
                inspectAsset(entry.getName(), assetFindings);
                boolean isDescriptor = descriptorMetadataExtractor.isDescriptor(entry.getName());
                boolean isClass = entry.getName().endsWith(".class") && entry.getSize() <= MAX_CLASS_BYTES;
                boolean isChannelCarrier = looksLikeChannelCarrier(entry.getName());
                if (isDescriptor || isClass || isChannelCarrier) {
                    byte[] entryBytes;
                    try (InputStream input = jar.getInputStream(entry)) {
                        entryBytes = input.readAllBytes();
                    }

                    if (isDescriptor) {
                        descriptorMetadata.add(descriptorMetadataExtractor.extract(entry.getName(), entryBytes));
                    }
                    if (isClass) {
                        try {
                            classFacts.add(extractor.extract(entryBytes));
                        } catch (RuntimeException ignored) {
                            assetFindings.add(new AssetFinding(entry.getName(), "class", "Unreadable bytecode", "ASM could not parse this class; it may be packed, corrupted, or intentionally malformed."));
                        }
                    }
                    if (isChannelCarrier) {
                        fallbackChannelFindings.addAll(extractChannelFindingsFromRawBytes(entry.getName(), entryBytes));
                    }
                }
            }
        }

        List<Indicator> indicators = detectorRegistry.detect(new AnalysisContext(classFacts, assetFindings, jarEntryNames, manifest)).stream()
                .sorted(Comparator.comparing(Indicator::severity).reversed().thenComparing(Indicator::confidence).reversed())
                .toList();
        List<ArtifactClassification> artifactClassifications = artifactClassifier.classify(classFacts, assetFindings, jarEntryNames, manifest);
        int riskScore = calculateRiskScore(indicators, classFacts, assetFindings);
        RiskLevel riskLevel = riskLevel(riskScore);
        List<String> categories = behaviorCategories(classFacts, indicators, assetFindings, artifactClassifications);
        List<PackageSummary> packages = packageSummaries(classFacts);

        List<ClassRelationship> relationships = classFacts.stream()
                .flatMap(facts -> facts.relationships().stream())
                .limit(1000)
                .toList();
        List<MethodCallEdge> methodCallEdges = classFacts.stream()
                .flatMap(facts -> facts.methodCalls().stream())
                .filter(edge -> isInterestingCall(edge.targetOwner(), edge.targetMethod()))
                .limit(1200)
                .toList();

        List<ChannelFinding> channelFindings = classFacts.stream()
                .flatMap(facts -> facts.channelFindings().stream())
                .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
        channelFindings.addAll(fallbackChannelFindings);
        channelFindings = channelFindings.stream()
                .distinct()
                .limit(200)
                .toList();

        Map<String, Object> aiSignals = aiReadySignals(classFacts, indicators, assetFindings);
        String summary = summarize(fileName, classFacts.size(), indicators, riskLevel);
        List<EndpointFinding> endpointFindings = List.of();
        List<DependencyArtifact> dependencies = List.of();

        return new JarAnalysisReport(
                UUID.randomUUID().toString(),
                fileName,
                Files.size(jarPath),
                sha256(jarPath),
                Instant.now(),
                riskLevel,
                riskScore,
                summary,
                manifest,
                categories,
                artifactClassifications,
                descriptorMetadata,
                channelFindings,
                indicators,
                packages,
                relationships,
                methodCallEdges,
                assetFindings,
                resourceSummary,
                endpointFindings,
                dependencies,
                aiSignals
        );
    }

    private String sha256(Path path) throws IOException {
        try (InputStream input = Files.newInputStream(path)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            StringBuilder hex = new StringBuilder();
            for (byte value : digest.digest()) {
                hex.append(String.format("%02x", value));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IOException("SHA-256 digest algorithm is unavailable.", exception);
        }
    }

    private void classifyResource(Map<String, Long> resourceSummary, String name) {
        String type = "other";
        if (name.endsWith(".class")) {
            type = "classes";
        } else if (name.endsWith(".json")) {
            type = "json";
        } else if (name.endsWith(".properties") || name.endsWith(".lang")) {
            type = "translations";
        } else if (name.endsWith(".png") || name.endsWith(".jpg") || name.endsWith(".webp")) {
            type = "images";
        } else if (name.endsWith(".dll") || name.endsWith(".so") || name.endsWith(".dylib")) {
            type = "native-libraries";
        } else if (name.startsWith("META-INF/")) {
            type = "metadata";
        }
        resourceSummary.merge(type, 1L, Long::sum);
    }

    private void inspectAsset(String name, List<AssetFinding> findings) {
        String lowered = name.toLowerCase(Locale.ROOT);
        if (lowered.contains("assets/") || lowered.contains("lang/") || lowered.endsWith(".lang") || lowered.endsWith(".properties")) {
            if (containsAny(lowered, "killaura", "aimbot", "xray", "reach", "velocity", "autoclick", "esp", "fly", "speed")) {
                findings.add(new AssetFinding(name, "translation-key", "Cheat capability vocabulary", "The asset path exposes feature terminology commonly associated with cheat-client modules."));
            } else if (containsAny(lowered, "module", "client", "hack", "bypass", "exploit")) {
                findings.add(new AssetFinding(name, "asset", "Hidden module or client vocabulary", "Asset naming suggests module metadata or concealed functionality that should be inspected manually."));
            }
        }
        if (lowered.endsWith(".dll") || lowered.endsWith(".so") || lowered.endsWith(".dylib")) {
            findings.add(new AssetFinding(name, "native", "Bundled native library", "Native binaries expand runtime capability beyond JVM bytecode and increase sandboxing requirements."));
        }
    }

    private int calculateRiskScore(List<Indicator> indicators, List<ClassBytecodeFacts> facts, List<AssetFinding> assets) {
        int score = indicators.stream()
                .mapToInt(indicator -> (int) Math.round(indicator.severity() * 8 * (indicator.confidence() / 100.0)))
                .sum();
        score += Math.min(12, assets.size() * 2);
        score += facts.stream().anyMatch(ClassBytecodeFacts::hasMinecraftSignals) ? 4 : 0;
        return Math.min(100, score);
    }

    private RiskLevel riskLevel(int score) {
        if (score >= 75) {
            return RiskLevel.CRITICAL;
        }
        if (score >= 45) {
            return RiskLevel.ELEVATED;
        }
        if (score >= 20) {
            return RiskLevel.GUARDED;
        }
        return RiskLevel.LOW;
    }

    private List<String> behaviorCategories(List<ClassBytecodeFacts> facts, List<Indicator> indicators, List<AssetFinding> assets, List<ArtifactClassification> classifications) {
        Set<String> categories = new HashSet<>();
        for (Indicator indicator : indicators) {
            categories.add(indicator.category());
        }
        for (ArtifactClassification classification : classifications) {
            categories.add(classification.family());
        }
        if (facts.stream().anyMatch(ClassBytecodeFacts::hasMinecraftSignals)) {
            categories.add("Minecraft/JVM Modding");
        }
        if (!assets.isEmpty()) {
            categories.add("Asset Intelligence");
        }
        return categories.stream().sorted().toList();
    }

    private List<PackageSummary> packageSummaries(List<ClassBytecodeFacts> facts) {
        Map<String, List<ClassBytecodeFacts>> byPackage = new HashMap<>();
        for (ClassBytecodeFacts fact : facts) {
            byPackage.computeIfAbsent(fact.packageName(), ignored -> new ArrayList<>()).add(fact);
        }
        return byPackage.entrySet().stream()
                .map(entry -> new PackageSummary(entry.getKey().isBlank() ? "(default)" : entry.getKey(), entry.getValue().size(), suspiciousSignals(entry.getValue())))
                .sorted(Comparator.comparing(PackageSummary::suspiciousSignalCount).reversed().thenComparing(PackageSummary::classCount).reversed())
                .limit(100)
                .toList();
    }

    private int suspiciousSignals(List<ClassBytecodeFacts> facts) {
        int signals = 0;
        for (ClassBytecodeFacts fact : facts) {
            signals += fact.usesReflection() ? 1 : 0;
            signals += fact.usesClassLoader() ? 1 : 0;
            signals += fact.usesNetworking() ? 1 : 0;
            signals += fact.usesInstrumentation() ? 1 : 0;
            signals += fact.usesNativeAccess() ? 1 : 0;
            signals += fact.usesProcessExecution() ? 1 : 0;
            signals += fact.hasPacketSignals() ? 1 : 0;
        }
        return signals;
    }

    private Map<String, Object> aiReadySignals(List<ClassBytecodeFacts> facts, List<Indicator> indicators, List<AssetFinding> assets) {
        Map<String, Object> signals = new LinkedHashMap<>();
        signals.put("featureVectorVersion", "static-v1");
        signals.put("classCount", facts.size());
        signals.put("methodCount", facts.stream().mapToInt(ClassBytecodeFacts::methodCount).sum());
        signals.put("fieldCount", facts.stream().mapToInt(ClassBytecodeFacts::fieldCount).sum());
        signals.put("indicatorCount", indicators.size());
        signals.put("assetFindingCount", assets.size());
        signals.put("reflectionClassRatio", ratio(facts, ClassBytecodeFacts::usesReflection));
        signals.put("networkClassRatio", ratio(facts, ClassBytecodeFacts::usesNetworking));
        signals.put("classloaderClassRatio", ratio(facts, ClassBytecodeFacts::usesClassLoader));
        signals.put("packetSignalRatio", ratio(facts, ClassBytecodeFacts::hasPacketSignals));
        signals.put("explanation", "These normalized signals are designed for downstream embeddings, clustering, anomaly detection, and supervised malware or cheat-client classifiers.");
        return signals;
    }

    private double ratio(List<ClassBytecodeFacts> facts, Predicate<ClassBytecodeFacts> predicate) {
        if (facts.isEmpty()) {
            return 0.0;
        }
        long matches = facts.stream().filter(predicate).count();
        return Math.round((matches / (double) facts.size()) * 1000.0) / 1000.0;
    }

    private String summarize(String fileName, int classCount, List<Indicator> indicators, RiskLevel riskLevel) {
        if (indicators.isEmpty()) {
            return fileName + " contains " + classCount + " classes and no high-confidence suspicious static indicators in the current ruleset.";
        }
        return fileName + " contains " + classCount + " classes and " + indicators.size() + " notable indicators. Overall static posture is " + riskLevel + ".";
    }

    private boolean isInterestingCall(String owner, String method) {
        String value = (owner + "." + method).toLowerCase(Locale.ROOT);
        return containsAny(value, "reflect", "classloader", "instrument", "netty", "socket", "url", "runtime.exec", "processbuilder", "packet", "mixin", "loadlibrary", "defineclass");
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static boolean looksLikeChannelCarrier(String entryName) {
        String lowered = entryName.toLowerCase(Locale.ROOT);
        return lowered.endsWith(".class")
                || lowered.endsWith(".json")
                || lowered.endsWith(".toml")
                || lowered.endsWith(".yml")
                || lowered.endsWith(".yaml")
                || lowered.endsWith(".properties")
                || lowered.endsWith(".lang")
                || lowered.endsWith(".txt")
                || lowered.endsWith(".mcmeta")
                || containsAny(lowered, "fabric.mod.json", "plugin.yml", "velocity-plugin.json", "bungee.yml", "mods.toml", "neoforge.mods.toml", "mixin");
    }

    private List<ChannelFinding> extractChannelFindingsFromRawBytes(String entryName, byte[] classBytes) {
        if (classBytes == null || classBytes.length == 0 || classBytes.length > RAW_SCAN_LIMIT) {
            return List.of();
        }
        String ascii = new String(classBytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\b[A-Za-z0-9_.-]{2,48}:[A-Za-z0-9_./-]{1,120}\\b");
        java.util.regex.Matcher matcher = pattern.matcher(ascii);
        String sourceClass = entryName.endsWith(".class")
                ? entryName.substring(0, entryName.length() - 6).replace('/', '.')
                : entryName;
        String sourceMethod = entryName.endsWith(".class") ? "<raw-bytes>" : "<resource-bytes>";
        String system = entryName.endsWith(".class") ? "raw-bytecode-channel" : "raw-resource-channel";
        List<ChannelFinding> findings = new ArrayList<>();
        int matched = 0;
        while (matcher.find() && matched < 24) {
            String channel = matcher.group();
            if (!isLikelyPluginChannel(channel)) {
                continue;
            }
            findings.add(new ChannelFinding(system, "unknown", channel, sourceClass, sourceMethod));
            matched++;
        }
        return findings;
    }

    private static boolean isLikelyPluginChannel(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        if (!value.contains(":")) {
            return false;
        }
        if (containsAny(value, "http:", "https:", "urn:")) {
            return false;
        }
        if (containsAny(value.toLowerCase(Locale.ROOT),
                "textures/", "texture/", "models/", "lang/", "assets/", "shaders/", "sounds/",
                ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".ogg", ".wav", ".mp3", ".json", ".mcmeta")) {
            return false;
        }
        String[] parts = value.split(":", 2);
        if (parts.length != 2) {
            return false;
        }
        String namespace = parts[0];
        String path = parts[1];
        if (!namespace.matches("[A-Za-z0-9_.-]{2,48}")) {
            return false;
        }
        if (!path.matches("[A-Za-z0-9_./-]{1,120}")) {
            return false;
        }
        return true;
    }
}
