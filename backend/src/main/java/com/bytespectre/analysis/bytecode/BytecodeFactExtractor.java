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
        for (AbstractInsnNode instruction : method.instructions) {
            if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                lastString = value;
                inspectString(facts, value);
                continue;
            }
            if (instruction instanceof MethodInsnNode call) {
                inspectCall(facts, sourceMethod, call);
                maybeCaptureChannel(facts, sourceMethod, call, lastString);
                lastString = null;
            } else {
                // Reset once we move past the load and it wasn't immediately consumed by an invoke.
                if (instruction.getOpcode() != -1) {
                    lastString = null;
                }
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

    private void maybeCaptureChannel(ClassBytecodeFacts facts, String sourceMethod, MethodInsnNode call, String lastString) {
        if (lastString == null || lastString.isBlank() || lastString.length() > 80) {
            return;
        }
        String owner = internalToJava(call.owner);
        if (owner.equals("org.bukkit.plugin.messaging.Messenger") || owner.equals("org.bukkit.plugin.messaging.StandardMessenger")) {
            if (call.name.equals("registerOutgoingPluginChannel")) {
                facts.channelFindings().add(new ChannelFinding("bukkit-plugin-messaging", "outgoing", lastString, facts.className(), sourceMethod));
            } else if (call.name.equals("registerIncomingPluginChannel")) {
                facts.channelFindings().add(new ChannelFinding("bukkit-plugin-messaging", "incoming", lastString, facts.className(), sourceMethod));
            }
        }
        // Heuristic: recognize Minecraft namespaced plugin channels in string literals.
        if (lastString.contains(":") && lastString.matches("[a-z0-9_.-]+:[a-z0-9_./-]+")) {
            facts.channelFindings().add(new ChannelFinding("minecraft-plugin-channel", "unknown", lastString, facts.className(), sourceMethod));
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
