package com.bytespectre.sandbox;

import java.lang.instrument.Instrumentation;

public final class SandboxAgent {
    private SandboxAgent() {
    }

    public static void premain(String agentArgs, Instrumentation instrumentation) {
        install("premain", agentArgs, instrumentation);
    }

    public static void agentmain(String agentArgs, Instrumentation instrumentation) {
        install("agentmain", agentArgs, instrumentation);
    }

    private static void install(String mode, String agentArgs, Instrumentation instrumentation) {
        SandboxEventSink sink = new SandboxEventSink(agentArgs == null ? "stdout" : agentArgs);
        sink.emit("agent.install", "mode=" + mode + ", loadedClasses=" + instrumentation.getAllLoadedClasses().length);
        instrumentation.addTransformer(new SandboxClassLoadTransformer(sink), true);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> sink.emit("agent.shutdown", "ByteSpectre sandbox agent detached"), "bytespectre-sandbox-shutdown"));
    }
}

