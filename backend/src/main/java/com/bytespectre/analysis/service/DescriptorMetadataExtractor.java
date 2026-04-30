package com.bytespectre.analysis.service;

import com.bytespectre.analysis.model.DescriptorMetadata;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class DescriptorMetadataExtractor {
    private static final int MAX_DESCRIPTOR_BYTES = 256 * 1024;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public boolean isDescriptor(String path) {
        String lowered = path.toLowerCase();
        return lowered.endsWith("fabric.mod.json")
                || lowered.endsWith("quilt.mod.json")
                || lowered.endsWith("velocity-plugin.json")
                || lowered.endsWith("plugin.yml")
                || lowered.endsWith("paper-plugin.yml")
                || lowered.endsWith("bungee.yml")
                || lowered.endsWith("mods.toml")
                || lowered.endsWith("neoforge.mods.toml")
                || lowered.endsWith("mcmod.info");
    }

    public DescriptorMetadata extract(String path, byte[] bytes) {
        if (bytes.length > MAX_DESCRIPTOR_BYTES) {
            return new DescriptorMetadata(path, descriptorType(path), Map.of("status", "descriptor too large to parse inline"));
        }
        String content = new String(bytes, StandardCharsets.UTF_8);
        Map<String, String> fields = path.toLowerCase().endsWith(".json") ? parseJson(content) : parseKeyValue(content);
        return new DescriptorMetadata(path, descriptorType(path), fields);
    }

    private Map<String, String> parseJson(String content) {
        try {
            Object parsed = objectMapper.readValue(content, new TypeReference<>() {
            });
            Map<String, String> flattened = new LinkedHashMap<>();
            flattenJson("", parsed, flattened);
            return limit(flattened);
        } catch (IOException ignored) {
            return Map.of("parseError", "JSON descriptor could not be parsed");
        }
    }

    @SuppressWarnings("unchecked")
    private void flattenJson(String prefix, Object value, Map<String, String> output) {
        if (output.size() >= 24 || value == null) {
            return;
        }
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = prefix.isBlank() ? String.valueOf(entry.getKey()) : prefix + "." + entry.getKey();
                flattenJson(key, entry.getValue(), output);
            }
        } else if (value instanceof Iterable<?> iterable) {
            int index = 0;
            for (Object item : iterable) {
                flattenJson(prefix + "[" + index + "]", item, output);
                index++;
                if (index >= 5) {
                    break;
                }
            }
        } else {
            output.put(prefix, String.valueOf(value));
        }
    }

    private Map<String, String> parseKeyValue(String content) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (String line : content.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isBlank() || trimmed.startsWith("#") || trimmed.startsWith("[[")) {
                continue;
            }
            int split = trimmed.indexOf('=');
            if (split < 0) {
                split = trimmed.indexOf(':');
            }
            if (split > 0) {
                String key = trimmed.substring(0, split).trim();
                String value = trimmed.substring(split + 1).trim().replaceAll("^['\"]|['\"]$", "");
                if (!key.isBlank() && !value.isBlank()) {
                    fields.put(key, value);
                }
            }
            if (fields.size() >= 24) {
                break;
            }
        }
        return fields.isEmpty() ? Map.of("status", "descriptor found; no simple key/value fields extracted") : fields;
    }

    private Map<String, String> limit(Map<String, String> fields) {
        Map<String, String> limited = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            limited.put(entry.getKey(), entry.getValue());
            if (limited.size() >= 24) {
                break;
            }
        }
        return limited;
    }

    private String descriptorType(String path) {
        String lowered = path.toLowerCase();
        if (lowered.endsWith("fabric.mod.json")) {
            return "Fabric mod descriptor";
        }
        if (lowered.endsWith("quilt.mod.json")) {
            return "Quilt mod descriptor";
        }
        if (lowered.endsWith("mods.toml") || lowered.endsWith("neoforge.mods.toml")) {
            return "Forge/NeoForge mod descriptor";
        }
        if (lowered.endsWith("plugin.yml")) {
            return "Bukkit/Spigot plugin descriptor";
        }
        if (lowered.endsWith("paper-plugin.yml")) {
            return "Paper plugin descriptor";
        }
        if (lowered.endsWith("velocity-plugin.json")) {
            return "Velocity plugin descriptor";
        }
        if (lowered.endsWith("bungee.yml")) {
            return "BungeeCord plugin descriptor";
        }
        return "Game/JVM descriptor";
    }
}

