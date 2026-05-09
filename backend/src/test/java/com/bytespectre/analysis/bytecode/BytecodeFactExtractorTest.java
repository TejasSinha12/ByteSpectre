package com.bytespectre.analysis.bytecode;

import com.bytespectre.analysis.model.ChannelFinding;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import static org.assertj.core.api.Assertions.assertThat;

class BytecodeFactExtractorTest {

    @Test
    void capturesFabricChannelFromIdentifierFactoryAndRegistration() {
        byte[] classBytes = buildFabricRegistrationClass();

        ClassBytecodeFacts facts = new BytecodeFactExtractor().extract(classBytes);

        assertThat(facts.channelFindings())
                .anySatisfy(finding -> {
                    assertThat(finding.system()).isEqualTo("fabric-networking");
                    assertThat(finding.direction()).isEqualTo("incoming");
                    assertThat(finding.channel()).isEqualTo("voicechat:state");
                });
    }

    @Test
    void capturesBukkitOutgoingRegistrationChannel() {
        byte[] classBytes = buildBukkitRegistrationClass();

        ClassBytecodeFacts facts = new BytecodeFactExtractor().extract(classBytes);

        assertThat(facts.channelFindings())
                .contains(new ChannelFinding(
                        "bukkit-plugin-messaging",
                        "outgoing",
                        "BungeeCord",
                        "test.BukkitChannelSample",
                        "register()V"
                ));
    }

    private static byte[] buildFabricRegistrationClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "test/FabricChannelSample", null, "java/lang/Object", null);

        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "register", "()V", null, null);
        method.visitCode();
        method.visitLdcInsn("voicechat");
        method.visitLdcInsn("state");
        method.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                "net/minecraft/util/Identifier",
                "of",
                "(Ljava/lang/String;Ljava/lang/String;)Lnet/minecraft/util/Identifier;",
                false
        );
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                "net/fabricmc/fabric/api/networking/v1/ServerPlayNetworking",
                "registerGlobalReceiver",
                "(Lnet/minecraft/util/Identifier;Ljava/lang/Object;)V",
                false
        );
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] buildBukkitRegistrationClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "test/BukkitChannelSample", null, "java/lang/Object", null);

        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "register", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitLdcInsn("BungeeCord");
        method.visitMethodInsn(
                Opcodes.INVOKEINTERFACE,
                "org/bukkit/plugin/messaging/Messenger",
                "registerOutgoingPluginChannel",
                "(Lorg/bukkit/plugin/Plugin;Ljava/lang/String;)V",
                true
        );
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }
}
