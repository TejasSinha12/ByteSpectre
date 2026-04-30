package com.bytespectre.analysis;

import com.bytespectre.analysis.model.JarAnalysisReport;
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

        JarAnalysisReport report = new JarAnalysisService().analyze(jar);

        assertThat(report.fileName()).endsWith(".jar");
        assertThat(report.resourceSummary()).containsEntry("translations", 1L);
        assertThat(report.assetFindings()).isNotEmpty();
    }
}

