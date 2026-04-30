package com.bytespectre.sandbox;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.Set;

final class SandboxClassLoadTransformer implements ClassFileTransformer {
    private static final Set<String> INTERESTING_PREFIXES = Set.of(
            "java/lang/reflect/",
            "java/lang/instrument/",
            "java/net/",
            "javax/net/",
            "io/netty/",
            "org/objectweb/asm/",
            "org/spongepowered/asm/mixin/",
            "net/minecraft/",
            "org/bukkit/",
            "net/fabricmc/",
            "net/minecraftforge/"
    );

    private final SandboxEventSink sink;

    SandboxClassLoadTransformer(SandboxEventSink sink) {
        this.sink = sink;
    }

    @Override
    public byte[] transform(
            Module module,
            ClassLoader loader,
            String className,
            Class<?> classBeingRedefined,
            ProtectionDomain protectionDomain,
            byte[] classfileBuffer
    ) throws IllegalClassFormatException {
        if (className != null && isInteresting(className)) {
            sink.emit("class.load", className.replace('/', '.') + " loader=" + loaderName(loader));
        }
        return null;
    }

    private boolean isInteresting(String className) {
        for (String prefix : INTERESTING_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private String loaderName(ClassLoader loader) {
        return loader == null ? "bootstrap" : loader.getClass().getName();
    }
}

