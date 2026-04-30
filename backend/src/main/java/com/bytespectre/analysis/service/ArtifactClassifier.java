package com.bytespectre.analysis.service;

import com.bytespectre.analysis.bytecode.ClassBytecodeFacts;
import com.bytespectre.analysis.model.ArtifactClassification;
import com.bytespectre.analysis.model.AssetFinding;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class ArtifactClassifier {
    public List<ArtifactClassification> classify(
            List<ClassBytecodeFacts> classFacts,
            List<AssetFinding> assetFindings,
            List<String> jarEntryNames,
            Map<String, String> manifest
    ) {
        List<String> loweredEntries = jarEntryNames.stream()
                .map(entry -> entry.toLowerCase(Locale.ROOT))
                .toList();
        List<String> loweredPackages = classFacts.stream()
                .map(fact -> fact.className().toLowerCase(Locale.ROOT))
                .toList();

        List<ArtifactClassification> classifications = new ArrayList<>();
        detectFabricMod(classifications, loweredEntries, loweredPackages);
        detectForgeMod(classifications, loweredEntries, loweredPackages);
        detectBukkitPlugin(classifications, loweredEntries, loweredPackages);
        detectPaperPlugin(classifications, loweredEntries, loweredPackages);
        detectMinecraftClient(classifications, loweredEntries, loweredPackages, assetFindings);
        detectGamePlugin(classifications, loweredEntries, loweredPackages);
        detectJavaAgent(classifications, manifest);
        detectGenericJavaApplication(classifications, manifest, classFacts);

        if (classifications.isEmpty()) {
            classifications.add(new ArtifactClassification(
                    "artifact.unknown-java-archive",
                    "Unclassified Java Archive",
                    "Generic JVM",
                    42,
                    List.of("No known mod/plugin/client descriptors matched"),
                    "The archive is structurally valid for analysis, but ByteSpectre did not find enough metadata to classify it into a known game or JVM application family."
            ));
        }

        return classifications;
    }

    private void detectFabricMod(List<ArtifactClassification> classifications, List<String> entries, List<String> packages) {
        List<String> evidence = evidence(entries, "fabric.mod.json", "fabric.mod.json");
        if (!evidence.isEmpty() || containsAny(packages, "net.fabricmc", "fabric.api", "fabricloader")) {
            classifications.add(new ArtifactClassification(
                    "artifact.minecraft.fabric-mod",
                    "Minecraft Fabric Mod",
                    "Minecraft Mod",
                    evidence.isEmpty() ? 72 : 96,
                    evidence.isEmpty() ? List.of("Fabric package references") : evidence,
                    "Fabric metadata or loader references indicate a Minecraft mod targeting the Fabric ecosystem."
            ));
        }
    }

    private void detectForgeMod(List<ArtifactClassification> classifications, List<String> entries, List<String> packages) {
        List<String> evidence = evidence(entries, "meta-inf/mods.toml", "mods.toml");
        if (!evidence.isEmpty() || containsAny(packages, "net.minecraftforge", "minecraftforge", "fmlclientsetup")) {
            classifications.add(new ArtifactClassification(
                    "artifact.minecraft.forge-mod",
                    "Minecraft Forge Mod",
                    "Minecraft Mod",
                    evidence.isEmpty() ? 74 : 96,
                    evidence.isEmpty() ? List.of("Forge/FML package references") : evidence,
                    "Forge metadata or FML references indicate a Minecraft mod targeting Forge or NeoForge-style loading."
            ));
        }
    }

    private void detectBukkitPlugin(List<ArtifactClassification> classifications, List<String> entries, List<String> packages) {
        List<String> evidence = evidence(entries, "plugin.yml", "bukkit.yml");
        if (!evidence.isEmpty() || containsAny(packages, "org.bukkit", "org.spigotmc", "net.md_5.bungee")) {
            classifications.add(new ArtifactClassification(
                    "artifact.minecraft.bukkit-plugin",
                    "Bukkit/Spigot Plugin",
                    "Minecraft Server Plugin",
                    evidence.isEmpty() ? 70 : 95,
                    evidence.isEmpty() ? List.of("Bukkit/Spigot package references") : evidence,
                    "Plugin descriptors or Bukkit-family APIs indicate a server-side Minecraft plugin."
            ));
        }
    }

    private void detectPaperPlugin(List<ArtifactClassification> classifications, List<String> entries, List<String> packages) {
        List<String> evidence = evidence(entries, "paper-plugin.yml");
        if (!evidence.isEmpty() || containsAny(packages, "io.papermc.paper", "paperlib")) {
            classifications.add(new ArtifactClassification(
                    "artifact.minecraft.paper-plugin",
                    "Paper Plugin",
                    "Minecraft Server Plugin",
                    evidence.isEmpty() ? 72 : 97,
                    evidence.isEmpty() ? List.of("Paper API package references") : evidence,
                    "Paper plugin metadata or API references indicate a Paper server plugin."
            ));
        }
    }

    private void detectMinecraftClient(List<ArtifactClassification> classifications, List<String> entries, List<String> packages, List<AssetFinding> assets) {
        boolean clientPackages = containsAny(packages, "net.minecraft.client", "minecraft.client", "client.renderer", "client.gui", "lwjgl");
        boolean moduleAssets = assets.stream().anyMatch(asset -> asset.signal().toLowerCase(Locale.ROOT).contains("cheat") || asset.signal().toLowerCase(Locale.ROOT).contains("module"));
        boolean clientAssets = containsAny(entries, "assets/minecraft", "assets/realms", "pack.mcmeta");
        if (clientPackages || moduleAssets || clientAssets) {
            List<String> evidence = new ArrayList<>();
            if (clientPackages) {
                evidence.add("Minecraft client-side package references");
            }
            if (moduleAssets) {
                evidence.add("Module or cheat-client vocabulary in assets");
            }
            if (clientAssets) {
                evidence.add("Minecraft asset namespace resources");
            }
            classifications.add(new ArtifactClassification(
                    "artifact.minecraft.client-like",
                    "Minecraft Client-Side JAR",
                    "Minecraft Client",
                    moduleAssets ? 86 : 68,
                    evidence,
                    "Client package and asset signals suggest the JAR participates in client-side Minecraft behavior, rendering, UI, modules, or bundled game assets."
            ));
        }
    }

    private void detectGamePlugin(List<ArtifactClassification> classifications, List<String> entries, List<String> packages) {
        if (containsAny(entries, "velocity-plugin.json") || containsAny(packages, "com.velocitypowered.api")) {
            classifications.add(new ArtifactClassification(
                    "artifact.minecraft.velocity-plugin",
                    "Velocity Proxy Plugin",
                    "Minecraft Proxy Plugin",
                    containsAny(entries, "velocity-plugin.json") ? 96 : 72,
                    containsAny(entries, "velocity-plugin.json") ? List.of("velocity-plugin.json") : List.of("Velocity API package references"),
                    "Velocity metadata or API references indicate a Minecraft proxy plugin."
            ));
        }
        if (containsAny(entries, "bungee.yml") || containsAny(packages, "net.md_5.bungee.api")) {
            classifications.add(new ArtifactClassification(
                    "artifact.minecraft.bungeecord-plugin",
                    "BungeeCord Plugin",
                    "Minecraft Proxy Plugin",
                    containsAny(entries, "bungee.yml") ? 95 : 72,
                    containsAny(entries, "bungee.yml") ? List.of("bungee.yml") : List.of("BungeeCord API package references"),
                    "BungeeCord metadata or API references indicate a Minecraft proxy plugin."
            ));
        }
    }

    private void detectJavaAgent(List<ArtifactClassification> classifications, Map<String, String> manifest) {
        if (manifest.keySet().stream().anyMatch(key -> key.equalsIgnoreCase("Premain-Class") || key.equalsIgnoreCase("Agent-Class"))) {
            classifications.add(new ArtifactClassification(
                    "artifact.jvm.java-agent",
                    "Java Agent",
                    "JVM Instrumentation",
                    98,
                    List.of("Premain-Class or Agent-Class manifest attribute"),
                    "The manifest exposes JVM agent entrypoints, so the artifact can attach to or instrument JVM processes."
            ));
        }
    }

    private void detectGenericJavaApplication(List<ArtifactClassification> classifications, Map<String, String> manifest, List<ClassBytecodeFacts> classFacts) {
        boolean hasMainClass = manifest.keySet().stream().anyMatch(key -> key.equalsIgnoreCase("Main-Class"));
        if (hasMainClass || !classFacts.isEmpty()) {
            classifications.add(new ArtifactClassification(
                    "artifact.jvm.application",
                    hasMainClass ? "Executable Java Application" : "Java Library",
                    "Generic JVM",
                    hasMainClass ? 88 : 55,
                    hasMainClass ? List.of("Main-Class manifest attribute") : List.of(classFacts.size() + " parsed class files"),
                    hasMainClass ? "The manifest identifies a launchable Java application." : "The archive contains JVM bytecode but no stronger application family descriptor was required for this generic classification."
            ));
        }
    }

    private List<String> evidence(List<String> values, String... exactMatches) {
        List<String> matches = new ArrayList<>();
        for (String value : values) {
            for (String exactMatch : exactMatches) {
                if (value.equals(exactMatch) || value.endsWith("/" + exactMatch)) {
                    matches.add(value);
                }
            }
        }
        return matches;
    }

    private boolean containsAny(List<String> values, String... needles) {
        for (String value : values) {
            for (String needle : needles) {
                if (value.contains(needle)) {
                    return true;
                }
            }
        }
        return false;
    }
}

