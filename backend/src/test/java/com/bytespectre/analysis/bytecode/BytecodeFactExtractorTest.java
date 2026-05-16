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

    @Test
    void capturesFabricChannelFromStaticIdentifierFieldUsage() {
        byte[] classBytes = buildFabricStaticIdentifierClass();

        ClassBytecodeFacts facts = new BytecodeFactExtractor().extract(classBytes);

        assertThat(facts.channelFindings())
                .anySatisfy(finding -> {
                    assertThat(finding.system()).isEqualTo("fabric-networking");
                    assertThat(finding.channel()).isEqualTo("voicechat:state");
                });
    }

    @Test
    void capturesFabricChannelWhenIdentifierUsesStaticModIdString() {
        byte[] classBytes = buildFabricIdentifierFromStaticModIdClass();

        ClassBytecodeFacts facts = new BytecodeFactExtractor().extract(classBytes);

        assertThat(facts.channelFindings())
                .anySatisfy(finding -> assertThat(finding.channel()).isEqualTo("voicechat:state"));
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

    private static byte[] buildFabricStaticIdentifierClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "test/FabricStaticIdentifierSample", null, "java/lang/Object", null);

        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "CHAN", "Lnet/minecraft/util/Identifier;", null, null).visitEnd();

        MethodVisitor init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(0, 0);
        init.visitEnd();

        // static { CHAN = new Identifier("voicechat","state"); }
        MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitTypeInsn(Opcodes.NEW, "net/minecraft/util/Identifier");
        clinit.visitInsn(Opcodes.DUP);
        clinit.visitLdcInsn("voicechat");
        clinit.visitLdcInsn("state");
        clinit.visitMethodInsn(Opcodes.INVOKESPECIAL, "net/minecraft/util/Identifier", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", false);
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "test/FabricStaticIdentifierSample", "CHAN", "Lnet/minecraft/util/Identifier;");
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        // register() { ServerPlayNetworking.registerGlobalReceiver(CHAN, null); }
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "register", "()V", null, null);
        method.visitCode();
        method.visitFieldInsn(Opcodes.GETSTATIC, "test/FabricStaticIdentifierSample", "CHAN", "Lnet/minecraft/util/Identifier;");
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

    private static byte[] buildFabricIdentifierFromStaticModIdClass() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "test/FabricModIdIdentifierSample", null, "java/lang/Object", null);

        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "MODID", "Ljava/lang/String;", null, null).visitEnd();
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "CHAN", "Lnet/minecraft/util/Identifier;", null, null).visitEnd();

        MethodVisitor clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.visitCode();
        clinit.visitLdcInsn("voicechat");
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "test/FabricModIdIdentifierSample", "MODID", "Ljava/lang/String;");

        clinit.visitTypeInsn(Opcodes.NEW, "net/minecraft/util/Identifier");
        clinit.visitInsn(Opcodes.DUP);
        clinit.visitFieldInsn(Opcodes.GETSTATIC, "test/FabricModIdIdentifierSample", "MODID", "Ljava/lang/String;");
        clinit.visitLdcInsn("state");
        clinit.visitMethodInsn(Opcodes.INVOKESPECIAL, "net/minecraft/util/Identifier", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", false);
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "test/FabricModIdIdentifierSample", "CHAN", "Lnet/minecraft/util/Identifier;");
        clinit.visitInsn(Opcodes.RETURN);
        clinit.visitMaxs(0, 0);
        clinit.visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "register", "()V", null, null);
        method.visitCode();
        method.visitFieldInsn(Opcodes.GETSTATIC, "test/FabricModIdIdentifierSample", "CHAN", "Lnet/minecraft/util/Identifier;");
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
