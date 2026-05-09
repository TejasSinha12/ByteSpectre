package com.bytespectre.analysis.bytecode;

import com.bytespectre.analysis.model.ClassRelationship;
import com.bytespectre.analysis.model.ChannelFinding;
import com.bytespectre.analysis.model.MethodCallEdge;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayDeque;
import java.util.Deque;

public class BytecodeFactExtractor {
    public ClassBytecodeFacts extract(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode node = new ClassNode();
        reader.accept(node, ClassReader.SKIP_DEBUG);

        ClassBytecodeFacts facts = new ClassBytecodeFacts();
        facts.className(internalToJava(node.name));
        facts.methodCount(node.methods.size());
        facts.fieldCount(node.fields.size());

        if (node.superName != null) {
            facts.relationships().add(new ClassRelationship(facts.className(), internalToJava(node.superName), "extends"));
        }
        for (String interfaceName : node.interfaces) {
            facts.relationships().add(new ClassRelationship(facts.className(), internalToJava(interfaceName), "implements"));
        }

        facts.hasMinecraftSignals(containsAny(node.name, "minecraft", "net/minecraft", "bukkit", "spigot", "fabricmc", "forge"));
        facts.hasMixinSignals(containsAny(node.name, "mixin", "inject", "accessor"));

        for (MethodNode method : node.methods) {
            inspectMethod(facts, method);
        }

        facts.stringConstantCount(facts.stringConstants().size());
        return facts;
    }

    private void inspectMethod(ClassBytecodeFacts facts, MethodNode method) {
        String sourceMethod = method.name + method.desc;
        String lastString = null;
        Deque<String> recentStrings = new ArrayDeque<>();
        Deque<String> recentChannelCandidates = new ArrayDeque<>();
        for (AbstractInsnNode instruction : method.instructions) {
            if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                lastString = value;
                pushRecent(recentStrings, value);
                inspectString(facts, value);
                continue;
            }
            if (instruction instanceof MethodInsnNode call) {
                inspectCall(facts, sourceMethod, call);
                maybeCaptureChannel(facts, sourceMethod, call, lastString, recentStrings, recentChannelCandidates);
                lastString = null;
            }
        }
    }

    private void inspectCall(ClassBytecodeFacts facts, String sourceMethod, MethodInsnNode call) {
        String owner = internalToJava(call.owner);
        facts.methodCalls().add(new MethodCallEdge(facts.className(), sourceMethod, owner, call.name, call.desc));

        String ownerAndName = owner + "." + call.name;
        if (owner.startsWith("java.lang.reflect") || ownerAndName.equals("java.lang.Class.forName")) {
            facts.usesReflection(true);
        }
        if (owner.contains("ClassLoader") || ownerAndName.contains("defineClass") || ownerAndName.contains("loadClass")) {
            facts.usesClassLoader(true);
        }
        if (owner.startsWith("java.lang.instrument") || owner.contains("Instrumentation") || call.name.equals("premain") || call.name.equals("agentmain")) {
            facts.usesInstrumentation(true);
        }
        if (owner.startsWith("java.net") || owner.startsWith("javax.net") || owner.startsWith("io.netty") || owner.contains("WebSocket")) {
            facts.usesNetworking(true);
        }
        if (ownerAndName.equals("java.lang.System.load") || ownerAndName.equals("java.lang.System.loadLibrary")) {
            facts.usesNativeAccess(true);
        }
        if (ownerAndName.equals("java.lang.Runtime.exec") || ownerAndName.startsWith("java.lang.ProcessBuilder.")) {
            facts.usesProcessExecution(true);
        }
        if (containsAny(ownerAndName, "packet", "channel", "pipeline", "handler", "sendQueue")) {
            facts.hasPacketSignals(true);
        }
        if ((call.getOpcode() == Opcodes.INVOKEDYNAMIC) || containsAny(ownerAndName, "mixin", "inject", "callbackinfo")) {
            facts.hasMixinSignals(true);
        }
    }

    private void maybeCaptureChannel(
            ClassBytecodeFacts facts,
            String sourceMethod,
            MethodInsnNode call,
            String lastString,
            Deque<String> recentStrings,
            Deque<String> recentChannelCandidates
    ) {
        String owner = internalToJava(call.owner);
        String channelCandidate = resolveChannelCandidate(lastString, recentStrings, recentChannelCandidates);

        if (isIdentifierFactoryCall(owner, call.name)) {
            String identifierChannel = resolveIdentifierChannel(recentStrings);
            if (identifierChannel != null) {
                pushRecent(recentChannelCandidates, identifierChannel);
                addChannelFindingUnique(
                        facts,
                        new ChannelFinding("minecraft-plugin-channel", "unknown", identifierChannel, facts.className(), sourceMethod)
                );
            }
        }

        if (owner.equals("org.bukkit.plugin.messaging.Messenger") || owner.equals("org.bukkit.plugin.messaging.StandardMessenger")) {
            if (call.name.equals("registerOutgoingPluginChannel") && channelCandidate != null) {
                addChannelFindingUnique(
                        facts,
                        new ChannelFinding("bukkit-plugin-messaging", "outgoing", channelCandidate, facts.className(), sourceMethod)
                );
            } else if (call.name.equals("registerIncomingPluginChannel") && channelCandidate != null) {
                addChannelFindingUnique(
                        facts,
                        new ChannelFinding("bukkit-plugin-messaging", "incoming", channelCandidate, facts.className(), sourceMethod)
                );
            }
        }

        if (isFabricChannelRegistrationCall(owner, call.name) && channelCandidate != null) {
            addChannelFindingUnique(
                    facts,
                    new ChannelFinding("fabric-networking", inferFabricDirection(owner, call.name), channelCandidate, facts.className(), sourceMethod)
            );
        }

        // Heuristic: recognize Minecraft namespaced plugin channels in nearby string literals.
        if (channelCandidate != null && looksLikeNamespacedChannel(channelCandidate)) {
            addChannelFindingUnique(
                    facts,
                    new ChannelFinding("minecraft-plugin-channel", "unknown", channelCandidate, facts.className(), sourceMethod)
            );
        }
    }

    private static boolean isIdentifierFactoryCall(String owner, String methodName) {
        return owner.equals("net.minecraft.util.Identifier")
                && (methodName.equals("of")
                || methodName.equals("tryParse")
                || methodName.equals("fromNamespaceAndPath")
                || methodName.equals("<init>"));
    }

    private static boolean isFabricChannelRegistrationCall(String owner, String methodName) {
        if (!containsAny(owner, "fabricmc.fabric.api.networking", "fabric.api.networking")) {
            return false;
        }
        return containsAny(methodName, "register", "receiver", "handler", "payload", "channel");
    }

    private static String inferFabricDirection(String owner, String methodName) {
        String lowered = (owner + "." + methodName).toLowerCase();
        if (lowered.contains("server")) {
            return "incoming";
        }
        if (lowered.contains("client")) {
            return "outgoing";
        }
        if (lowered.contains("c2s")) {
            return "incoming";
        }
        if (lowered.contains("s2c")) {
            return "outgoing";
        }
        return "unknown";
    }

    private static String resolveIdentifierChannel(Deque<String> recentStrings) {
        String[] values = recentStrings.toArray(new String[0]);
        if (values.length >= 2) {
            String namespace = values[values.length - 2];
            String path = values[values.length - 1];
            if (looksLikeIdentifierParts(namespace, path)) {
                return namespace + ":" + path;
            }
        }
        String last = values.length > 0 ? values[values.length - 1] : null;
        return looksLikeNamespacedChannel(last) ? last : null;
    }

    private static boolean looksLikeIdentifierParts(String namespace, String path) {
        if (namespace == null || path == null) {
            return false;
        }
        return namespace.matches("[a-z0-9_.-]+") && path.matches("[a-z0-9_./-]+");
    }

    private static String resolveChannelCandidate(String lastString, Deque<String> recentStrings, Deque<String> recentChannelCandidates) {
        if (looksLikeNamespacedChannel(lastString)) {
            return lastString;
        }
        String derived = resolveIdentifierChannel(recentStrings);
        if (derived != null) {
            return derived;
        }
        for (String candidate : recentChannelCandidates) {
            if (looksLikeNamespacedChannel(candidate)) {
                return candidate;
            }
        }
        String fallback = lastString == null ? null : lastString.trim();
        if (fallback == null || fallback.isBlank() || fallback.length() > 120) {
            return null;
        }
        return fallback;
    }

    private static boolean looksLikeNamespacedChannel(String value) {
        return value != null
                && value.length() <= 120
                && value.contains(":")
                && value.matches("[a-z0-9_.-]+:[a-z0-9_./-]+");
    }

    private static void pushRecent(Deque<String> values, String value) {
        if (value == null || value.isBlank()) {
            return;
        }
        values.addLast(value);
        while (values.size() > 8) {
            values.removeFirst();
        }
    }

    private static void addChannelFindingUnique(ClassBytecodeFacts facts, ChannelFinding candidate) {
        boolean exists = facts.channelFindings().stream().anyMatch(existing ->
                existing.system().equals(candidate.system())
                        && existing.direction().equals(candidate.direction())
                        && existing.channel().equals(candidate.channel())
                        && existing.sourceClass().equals(candidate.sourceClass())
                        && existing.sourceMethod().equals(candidate.sourceMethod()));
        if (!exists) {
            facts.channelFindings().add(candidate);
        }
    }

    private void inspectString(ClassBytecodeFacts facts, String value) {
        if (value.length() > 2 && facts.stringConstants().size() < 500) {
            facts.stringConstants().add(value);
        }
        String lowered = value.toLowerCase();
        if (containsAny(lowered, "packet", "velocity", "reach", "aimbot", "killaura", "xray", "autoclicker", "session", "token", "webhook")) {
            facts.hasPacketSignals(true);
        }
        if (containsAny(lowered, "minecraft", "fabric", "forge", "bukkit", "spigot", "paper")) {
            facts.hasMinecraftSignals(true);
        }
    }

    private static boolean containsAny(String value, String... needles) {
        String lowered = value.toLowerCase();
        for (String needle : needles) {
            if (lowered.contains(needle.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private static String internalToJava(String value) {
        return value == null ? "" : value.replace('/', '.');
    }
}
