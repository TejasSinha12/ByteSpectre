package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.bytecode.ClassBytecodeFacts;
import com.bytespectre.analysis.model.Indicator;
import java.util.ArrayList;
import java.util.List;

class AggregateBytecodeDetector implements JarDetector {
    @Override
    public List<Indicator> detect(AnalysisContext context) {
        List<Indicator> indicators = new ArrayList<>();
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::usesReflection, "reflection", "Reflective access", "Reflection usage can hide call targets from simple static inspection.", 3, 78);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::usesClassLoader, "classloader", "Dynamic class loading", "Custom class loading can unpack payloads, inject classes, or bypass static discovery.", 5, 84);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::usesInstrumentation, "instrumentation", "JVM instrumentation API", "Instrumentation hooks can redefine classes, trace runtime behavior, or modify application execution.", 6, 88);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::usesNetworking, "networking", "Network behavior", "Network APIs indicate runtime communication that should be inspected in sandbox mode.", 4, 76);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::usesCryptography, "crypto", "Cryptography usage", "Crypto APIs are common in legitimate software but also used to encrypt payloads, strings, configs, and network traffic.", 4, 70);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::usesNativeAccess, "native", "Native library loading", "Native access can evade JVM-level controls and should be isolated.", 7, 92);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::usesProcessExecution, "process", "Process execution", "Launching host processes is high-risk behavior for untrusted JARs.", 8, 94);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::hasPacketSignals, "packet", "Packet or protocol manipulation", "Bytecode and strings suggest packet flow, Netty pipeline, or protocol manipulation.", 4, 72);
        addAggregateIndicator(indicators, context.classFacts(), ClassBytecodeFacts::hasMixinSignals, "mixin", "Mixin or injection markers", "Mixin/injection-style classes can modify host application behavior at runtime.", 4, 74);
        return indicators;
    }

    private void addAggregateIndicator(List<Indicator> indicators, List<ClassBytecodeFacts> facts, FactPredicate predicate, String id, String title, String explanation, int severity, int confidence) {
        List<String> classes = facts.stream()
                .filter(predicate::matches)
                .map(ClassBytecodeFacts::className)
                .limit(5)
                .toList();
        if (!classes.isEmpty()) {
            indicators.add(new Indicator("bytecode." + id, title, "Bytecode", severity, confidence, String.join(", ", classes), explanation));
        }
    }

    @FunctionalInterface
    private interface FactPredicate {
        boolean matches(ClassBytecodeFacts facts);
    }
}
