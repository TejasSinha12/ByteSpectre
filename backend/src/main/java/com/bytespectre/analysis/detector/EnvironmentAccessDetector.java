package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.model.Indicator;
import com.bytespectre.analysis.model.MethodCallEdge;
import java.util.List;

class EnvironmentAccessDetector implements JarDetector {
    @Override
    public List<Indicator> detect(AnalysisContext context) {
        List<String> evidence = context.classFacts().stream()
                .flatMap(fact -> fact.methodCalls().stream())
                .filter(this::isEnvironmentProbe)
                .map(edge -> edge.sourceClass() + "." + edge.sourceMethod() + " -> " + edge.targetOwner() + "." + edge.targetMethod())
                .limit(5)
                .toList();

        if (evidence.isEmpty()) {
            return List.of();
        }

        return List.of(new Indicator(
                "bytecode.environment-probing",
                "Environment and host probing",
                "Anti-Analysis",
                5,
                72,
                String.join(", ", evidence),
                "The artifact queries environment variables, system properties, management APIs, or host runtime state; benign apps may do this, but it is also common in anti-analysis and fingerprinting logic."
        ));
    }

    private boolean isEnvironmentProbe(MethodCallEdge edge) {
        String ownerAndMethod = edge.targetOwner() + "." + edge.targetMethod();
        return ownerAndMethod.equals("java.lang.System.getenv")
                || ownerAndMethod.equals("java.lang.System.getProperty")
                || edge.targetOwner().startsWith("java.lang.management")
                || edge.targetOwner().startsWith("com.sun.management")
                || edge.targetOwner().equals("java.net.NetworkInterface")
                || edge.targetOwner().equals("java.lang.management.ManagementFactory");
    }
}

