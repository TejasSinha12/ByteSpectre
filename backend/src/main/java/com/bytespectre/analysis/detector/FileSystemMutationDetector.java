package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.model.Indicator;
import com.bytespectre.analysis.model.MethodCallEdge;
import java.util.List;

class FileSystemMutationDetector implements JarDetector {
    @Override
    public List<Indicator> detect(AnalysisContext context) {
        List<String> evidence = context.classFacts().stream()
                .flatMap(fact -> fact.methodCalls().stream())
                .filter(this::isMutation)
                .map(edge -> edge.sourceClass() + "." + edge.sourceMethod() + " -> " + edge.targetOwner() + "." + edge.targetMethod())
                .limit(5)
                .toList();

        if (evidence.isEmpty()) {
            return List.of();
        }

        return List.of(new Indicator(
                "bytecode.filesystem-mutation",
                "Filesystem mutation capability",
                "Filesystem",
                5,
                74,
                String.join(", ", evidence),
                "The artifact can write, delete, copy, move, or chmod files. This is common in installers and launchers, but it should be reviewed for untrusted JARs."
        ));
    }

    private boolean isMutation(MethodCallEdge edge) {
        String owner = edge.targetOwner();
        String method = edge.targetMethod();
        return owner.equals("java.nio.file.Files") && List.of("write", "writeString", "delete", "deleteIfExists", "copy", "move", "createFile", "createDirectory", "setPosixFilePermissions").contains(method)
                || owner.equals("java.io.File") && List.of("delete", "mkdir", "mkdirs", "renameTo", "setExecutable", "setWritable").contains(method)
                || owner.equals("java.io.FileOutputStream")
                || owner.equals("java.io.FileWriter")
                || owner.equals("java.io.RandomAccessFile");
    }
}

