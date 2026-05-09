package com.bytespectre.analysis.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.benf.cfr.reader.api.SinkReturns;
import org.benf.cfr.reader.api.OutputSinkFactory.SinkClass;
import org.benf.cfr.reader.api.OutputSinkFactory.SinkType;
import org.springframework.stereotype.Service;

@Service
public class DecompileService {
    public byte[] decompileJarToZip(Path jarPath, boolean deobfuscate) throws IOException {
        Map<String, String> options = new HashMap<>();
        options.put("outputencoding", "UTF-8");
        options.put("comments", "false");
        if (deobfuscate) {
            // Deobfuscation-lite: identifier cleanup + duplicate member rename for readability.
            options.put("renameillegalidents", "true");
            options.put("renamedupmembers", "true");
            options.put("renamebadmembers", "true");
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
            OutputSinkFactory sinkFactory = new ZipSinkFactory(zip);
            CfrDriver driver = new CfrDriver.Builder()
                    .withOptions(options)
                    .withOutputSink(sinkFactory)
                    .build();
            driver.analyse(Collections.singletonList(jarPath.toString()));
        }
        return bytes.toByteArray();
    }

    private static final class ZipSinkFactory implements OutputSinkFactory {
        private final ZipOutputStream zip;

        private ZipSinkFactory(ZipOutputStream zip) {
            this.zip = zip;
        }

        @Override
        public List<SinkClass> getSupportedSinks(SinkType sinkType, java.util.Collection<SinkClass> available) {
            if (sinkType == SinkType.JAVA && available.contains(SinkClass.DECOMPILED)) {
                return List.of(SinkClass.DECOMPILED, SinkClass.STRING);
            }
            return List.of(SinkClass.STRING);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <T> Sink<T> getSink(SinkType sinkType, SinkClass sinkClass) {
            if (sinkType == SinkType.JAVA && sinkClass == SinkClass.DECOMPILED) {
                return item -> {
                    SinkReturns.Decompiled decompiled = (SinkReturns.Decompiled) item;
                    String path = toPath(decompiled.getPackageName(), decompiled.getClassName());
                    writeZip(path, decompiled.getJava());
                };
            }
            return ignore -> {};
        }

        private void writeZip(String path, String content) {
            try {
                ZipEntry entry = new ZipEntry(path);
                zip.putNextEntry(entry);
                zip.write(content.getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            } catch (IOException ignored) {
                // Best-effort sink.
            }
        }

        private String toPath(String packageName, String className) {
            String prefix = (packageName == null || packageName.isBlank()) ? "" : packageName.replace('.', '/') + "/";
            return "decompiled/" + prefix + className + ".java";
        }
    }
}
