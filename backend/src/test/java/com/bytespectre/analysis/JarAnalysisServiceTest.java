package com.bytespectre.analysis;

import com.bytespectre.analysis.model.JarAnalysisReport;
import com.bytespectre.analysis.detector.DetectorRegistry;
import com.bytespectre.analysis.service.ArtifactClassifier;
import com.bytespectre.analysis.service.DescriptorMetadataExtractor;
import com.bytespectre.analysis.service.JarAnalysisService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JarAnalysisServiceTest {
    @Test
    void analyzesEmptyJarWithoutFailing() throws Exception {
        Path jar = Files.createTempFile("bytespectre-test-", ".jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("assets/client/lang/en_us.lang"));
            output.write("module.killaura.name=Kill Aura".getBytes());
            output.closeEntry();
        }

        JarAnalysisReport report = service().analyze(jar);

        assertThat(report.fileName()).endsWith(".jar");
        assertThat(report.sha256()).hasSize(64);
        assertThat(report.resourceSummary()).containsEntry("translations", 1L);
        assertThat(report.assetFindings()).isNotEmpty();
    }

    @Test
    void reportsNativeAssetIndicatorWithConfidence() throws Exception {
        Path jar = Files.createTempFile("bytespectre-native-test-", ".jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("native/libpayload.dylib"));
            output.write(new byte[] {1, 2, 3});
            output.closeEntry();
        }

        JarAnalysisReport report = service().analyze(jar);

        assertThat(report.indicators())
                .anySatisfy(indicator -> {
                    assertThat(indicator.id()).isEqualTo("assets.native");
                    assertThat(indicator.confidence()).isGreaterThanOrEqualTo(80);
                });
    }

    @Test
    void classifiesFabricModFromDescriptor() throws Exception {
        Path jar = Files.createTempFile("bytespectre-fabric-test-", ".jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("fabric.mod.json"));
            output.write("{\"id\":\"spectre-test\"}".getBytes());
            output.closeEntry();
        }

        JarAnalysisReport report = service().analyze(jar);

        assertThat(report.artifactClassifications())
                .anySatisfy(classification -> {
                    assertThat(classification.id()).isEqualTo("artifact.minecraft.fabric-mod");
                    assertThat(classification.confidence()).isGreaterThanOrEqualTo(90);
                });
        assertThat(report.behaviorCategories()).contains("Minecraft Mod");
        assertThat(report.descriptorMetadata())
                .anySatisfy(descriptor -> {
                    assertThat(descriptor.type()).isEqualTo("Fabric mod descriptor");
                    assertThat(descriptor.fields()).containsEntry("id", "spectre-test");
                });
    }

    @Test
    void classifiesBukkitPluginFromDescriptor() throws Exception {
        Path jar = Files.createTempFile("bytespectre-bukkit-test-", ".jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("plugin.yml"));
            output.write("name: SpectrePlugin\nmain: test.Plugin\n".getBytes());
            output.closeEntry();
        }

        JarAnalysisReport report = service().analyze(jar);

        assertThat(report.artifactClassifications())
                .anySatisfy(classification -> {
                    assertThat(classification.id()).isEqualTo("artifact.minecraft.bukkit-plugin");
                    assertThat(classification.family()).isEqualTo("Minecraft Server Plugin");
                });
        assertThat(report.behaviorCategories()).contains("Minecraft Server Plugin");
    }

    private JarAnalysisService service() {
        return new JarAnalysisService(new DetectorRegistry(), new ArtifactClassifier(), new DescriptorMetadataExtractor());
    }
}
