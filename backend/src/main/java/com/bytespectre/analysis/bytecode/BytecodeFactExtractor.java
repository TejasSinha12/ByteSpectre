package com.bytespectre.analysis.bytecode;

import com.bytespectre.analysis.model.ClassRelationship;
import com.bytespectre.analysis.model.ChannelFinding;
import com.bytespectre.analysis.model.MethodCallEdge;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

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

        Map<String, StackValue> staticFieldConstants = new HashMap<>();

        // Two-pass: harvest static channel constants from <clinit> first, then look for usages.
        for (MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name)) {
                inspectMethod(facts, method, staticFieldConstants);
            }
        }
        for (MethodNode method : node.methods) {
            if (!"<clinit>".equals(method.name)) {
                inspectMethod(facts, method, staticFieldConstants);
            }
        }

        facts.stringConstantCount(facts.stringConstants().size());
        return facts;
    }

    private void inspectMethod(ClassBytecodeFacts facts, MethodNode method, Map<String, StackValue> staticFieldConstants) {
        String sourceMethod = method.name + method.desc;
        String lastString = null;
        Deque<String> recentStrings = new ArrayDeque<>();
        Deque<String> recentChannelCandidates = new ArrayDeque<>();
        Deque<StackValue> valueStack = new ArrayDeque<>();
        for (AbstractInsnNode instruction : method.instructions) {
            if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                lastString = value;
                pushRecent(recentStrings, value);
                inspectString(facts, value);
                valueStack.addLast(StackValue.string(value));
                continue;
            }
            if (instruction instanceof TypeInsnNode typeInsn && typeInsn.getOpcode() == Opcodes.NEW) {
                valueStack.addLast(StackValue.object(internalToJava(typeInsn.desc)));
                continue;
            }
            if (instruction instanceof InsnNode insn && insn.getOpcode() == Opcodes.DUP) {
                StackValue top = valueStack.peekLast();
                if (top != null) {
                    valueStack.addLast(top);
                }
                continue;
            }
            if (instruction instanceof FieldInsnNode fieldInsn) {
                handleFieldInsn(valueStack, staticFieldConstants, facts, sourceMethod, fieldInsn);
                continue;
            }
            if (instruction instanceof MethodInsnNode call) {
                inspectCall(facts, sourceMethod, call);
                maybeCaptureChannel(facts, sourceMethod, call, lastString, recentStrings, recentChannelCandidates, valueStack);
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
        if (owner.startsWith("javax.crypto")
                || owner.startsWith("java.security")
                || owner.startsWith("javax.security")
                || ownerAndName.contains("Cipher.getInstance")
                || ownerAndName.contains("MessageDigest.getInstance")) {
            facts.usesCryptography(true);
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
            Deque<String> recentChannelCandidates,
            Deque<StackValue> valueStack
    ) {
        String owner = internalToJava(call.owner);
        String channelCandidate = resolveChannelCandidate(lastString, recentStrings, recentChannelCandidates);

        String resolvedByStack = resolveAndSimulateCall(valueStack, owner, call.name, call.desc);
        if (resolvedByStack != null) {
            pushRecent(recentChannelCandidates, resolvedByStack);
            addChannelFindingUnique(
                    facts,
                    new ChannelFinding("minecraft-plugin-channel", "unknown", resolvedByStack, facts.className(), sourceMethod)
            );
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

        String callChannel = resolveChannelFromStackForRegistration(valueStack, owner, call.name, call.desc);
        if (callChannel != null) {
            channelCandidate = callChannel;
        }

        if (isFabricChannelRegistrationCall(owner, call.name) && channelCandidate != null) {
            addChannelFindingUnique(
                    facts,
                    new ChannelFinding("fabric-networking", inferFabricDirection(owner, call.name), channelCandidate, facts.className(), sourceMethod)
            );
        }

        if (isForgeChannelRegistrationCall(owner, call.name) && channelCandidate != null) {
            addChannelFindingUnique(
                    facts,
                    new ChannelFinding("forge-networking", "unknown", channelCandidate, facts.className(), sourceMethod)
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

    private static boolean isResourceLocationFactoryCall(String owner, String methodName) {
        return owner.equals("net.minecraft.resources.ResourceLocation")
                && (methodName.equals("<init>")
                || methodName.equals("fromNamespaceAndPath")
                || methodName.equals("tryParse")
                || methodName.equals("parse"));
    }

    private static boolean isFabricChannelRegistrationCall(String owner, String methodName) {
        if (!containsAny(owner, "fabricmc.fabric.api.networking", "fabric.api.networking")) {
            return false;
        }
        return containsAny(methodName, "register", "receiver", "handler", "payload", "channel");
    }

    private static boolean isForgeChannelRegistrationCall(String owner, String methodName) {
        // Forge/NeoForge commonly uses NetworkRegistry.newSimpleChannel or SimpleChannel registration.
        return containsAny(owner, "net.minecraftforge.network", "net.neoforged.neoforge.network")
                && containsAny(methodName, "newSimpleChannel", "registerMessage", "messageBuilder", "addNetworkChannel", "createChannel");
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

    private static void handleFieldInsn(
            Deque<StackValue> valueStack,
            Map<String, StackValue> staticFieldConstants,
            ClassBytecodeFacts facts,
            String sourceMethod,
            FieldInsnNode fieldInsn
    ) {
        String owner = internalToJava(fieldInsn.owner);
        String fieldKey = owner + "." + fieldInsn.name + ":" + fieldInsn.desc;
        if (fieldInsn.getOpcode() == Opcodes.GETSTATIC) {
            StackValue constant = staticFieldConstants.get(fieldKey);
            if (constant != null) {
                valueStack.addLast(constant);
            } else {
                valueStack.addLast(StackValue.unknown());
            }
            return;
        }
        if (fieldInsn.getOpcode() == Opcodes.PUTSTATIC) {
            StackValue top = pollLast(valueStack);
            if (top != null && (top.kind == StackKind.CHANNEL || top.kind == StackKind.STRING)) {
                staticFieldConstants.put(fieldKey, top);
                if (top.kind == StackKind.CHANNEL) {
                    addChannelFindingUnique(
                            facts,
                            new ChannelFinding("minecraft-plugin-channel", "unknown", top.value, facts.className(), sourceMethod)
                    );
                }
            }
            return;
        }

        // Non-static field accesses are ignored for now; push unknown to keep stack roughly aligned.
        if (fieldInsn.getOpcode() == Opcodes.GETFIELD) {
            valueStack.addLast(StackValue.unknown());
        } else if (fieldInsn.getOpcode() == Opcodes.PUTFIELD) {
            pollLast(valueStack);
        }
    }

    private static StackValue pollLast(Deque<StackValue> valueStack) {
        return valueStack.isEmpty() ? null : valueStack.removeLast();
    }

    private static String resolveAndSimulateCall(Deque<StackValue> valueStack, String owner, String methodName, String desc) {
        // Very small stack interpreter: we only care about known Identifier/ResourceLocation constructions/factories.
        if (isIdentifierFactoryCall(owner, methodName)) {
            String channel = tryPopIdentifierChannel(valueStack, methodName, desc);
            if (channel != null) {
                valueStack.addLast(StackValue.channel(channel));
                return channel;
            }
        }
        if (isResourceLocationFactoryCall(owner, methodName)) {
            String channel = tryPopResourceLocationChannel(valueStack, methodName, desc);
            if (channel != null) {
                valueStack.addLast(StackValue.channel(channel));
                return channel;
            }
        }
        // Otherwise, we don't understand the stack behavior; best-effort: clear a bit to avoid runaway.
        if (!valueStack.isEmpty() && valueStack.size() > 32) {
            while (valueStack.size() > 16) {
                valueStack.removeFirst();
            }
        }
        return null;
    }

    private static String resolveChannelFromStackForRegistration(Deque<StackValue> valueStack, String owner, String methodName, String desc) {
        // Fabric API: Identifier is commonly the first arg.
        if (isFabricChannelRegistrationCall(owner, methodName) && desc != null && desc.contains("Lnet/minecraft/util/Identifier;")) {
            StackValue candidate = findLastChannel(valueStack, 6);
            return candidate == null ? null : candidate.value;
        }
        // Forge API: ResourceLocation is commonly the first arg for newSimpleChannel.
        if (isForgeChannelRegistrationCall(owner, methodName) && desc != null && desc.contains("Lnet/minecraft/resources/ResourceLocation;")) {
            StackValue candidate = findLastChannel(valueStack, 6);
            return candidate == null ? null : candidate.value;
        }
        return null;
    }

    private static StackValue findLastChannel(Deque<StackValue> valueStack, int lookback) {
        if (valueStack.isEmpty()) {
            return null;
        }
        StackValue[] values = valueStack.toArray(new StackValue[0]);
        for (int i = values.length - 1; i >= 0 && lookback-- > 0; i--) {
            if (values[i].kind == StackKind.CHANNEL) {
                return values[i];
            }
        }
        return null;
    }

    private static String tryPopIdentifierChannel(Deque<StackValue> valueStack, String methodName, String desc) {
        // INVOKESTATIC Identifier.of(String,String) -> Identifier
        if (methodName.equals("of") && "(Ljava/lang/String;Ljava/lang/String;)Lnet/minecraft/util/Identifier;".equals(desc)) {
            StackValue path = pollLast(valueStack);
            StackValue namespace = pollLast(valueStack);
            if (namespace != null && path != null && namespace.kind == StackKind.STRING && path.kind == StackKind.STRING) {
                String ns = namespace.value;
                String p = path.value;
                if (looksLikeIdentifierParts(ns, p)) {
                    return ns + ":" + p;
                }
            }
            return null;
        }
        // new Identifier(String, String)
        if (methodName.equals("<init>") && "(Ljava/lang/String;Ljava/lang/String;)V".equals(desc)) {
            StackValue path = pollLast(valueStack);
            StackValue namespace = pollLast(valueStack);
            pollLast(valueStack); // consumes the invoked instance
            if (namespace != null && path != null && namespace.kind == StackKind.STRING && path.kind == StackKind.STRING) {
                String ns = namespace.value;
                String p = path.value;
                if (looksLikeIdentifierParts(ns, p)) {
                    // The other DUP'ed object ref would still be on stack; we don't model DUP, but we still emit channel.
                    return ns + ":" + p;
                }
            }
            return null;
        }
        // new Identifier(String) with namespaced form.
        if (methodName.equals("<init>") && "(Ljava/lang/String;)V".equals(desc)) {
            StackValue single = pollLast(valueStack);
            pollLast(valueStack); // instance
            if (single != null && single.kind == StackKind.STRING && looksLikeNamespacedChannel(single.value)) {
                return single.value;
            }
        }
        if ((methodName.equals("tryParse") || methodName.equals("of")) && desc != null && desc.equals("(Ljava/lang/String;)Lnet/minecraft/util/Identifier;")) {
            StackValue single = pollLast(valueStack);
            if (single != null && single.kind == StackKind.STRING && looksLikeNamespacedChannel(single.value)) {
                return single.value;
            }
        }
        return null;
    }

    private static String tryPopResourceLocationChannel(Deque<StackValue> valueStack, String methodName, String desc) {
        if (methodName.equals("<init>") && "(Ljava/lang/String;Ljava/lang/String;)V".equals(desc)) {
            StackValue path = pollLast(valueStack);
            StackValue namespace = pollLast(valueStack);
            pollLast(valueStack); // instance
            if (namespace != null && path != null && namespace.kind == StackKind.STRING && path.kind == StackKind.STRING) {
                String ns = namespace.value;
                String p = path.value;
                if (looksLikeIdentifierParts(ns, p)) {
                    return ns + ":" + p;
                }
            }
        }
        if ((methodName.equals("tryParse") || methodName.equals("parse")) && desc != null && desc.equals("(Ljava/lang/String;)Lnet/minecraft/resources/ResourceLocation;")) {
            StackValue single = pollLast(valueStack);
            if (single != null && single.kind == StackKind.STRING && looksLikeNamespacedChannel(single.value)) {
                return single.value;
            }
        }
        return null;
    }

    private enum StackKind {
        STRING,
        CHANNEL,
        OBJECT,
        UNKNOWN
    }

    private static final class StackValue {
        private final StackKind kind;
        private final String value;

        private StackValue(StackKind kind, String value) {
            this.kind = kind;
            this.value = value;
        }

        static StackValue string(String value) {
            return new StackValue(StackKind.STRING, value);
        }

        static StackValue channel(String value) {
            return new StackValue(StackKind.CHANNEL, value);
        }

        static StackValue object(String type) {
            return new StackValue(StackKind.OBJECT, type);
        }

        static StackValue unknown() {
            return new StackValue(StackKind.UNKNOWN, "");
        }
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
