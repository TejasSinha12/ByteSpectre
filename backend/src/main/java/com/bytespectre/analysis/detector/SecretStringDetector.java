package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.bytecode.ClassBytecodeFacts;
import com.bytespectre.analysis.model.Indicator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

class SecretStringDetector implements JarDetector {
    private static final Pattern TOKEN_SHAPE = Pattern.compile("(?i).*(token|secret|apikey|api_key|authorization|bearer|webhook|discord|session).*");

    @Override
    public List<Indicator> detect(AnalysisContext context) {
        List<String> evidence = context.classFacts().stream()
                .flatMap(fact -> fact.stringConstants().stream().map(value -> fact.className() + " :: " + summarize(value)))
                .filter(SecretStringDetector::looksSensitive)
                .limit(5)
                .toList();

        if (evidence.isEmpty()) {
            return List.of();
        }

        return List.of(new Indicator(
                "strings.secret-material",
                "Secret or webhook string material",
                "Credential Exposure",
                7,
                76,
                String.join(", ", evidence),
                "String constants include token, authorization, webhook, or session vocabulary that may expose credentials or command-and-control endpoints."
        ));
    }

    private static boolean looksSensitive(String value) {
        String lowered = value.toLowerCase(Locale.ROOT);
        return TOKEN_SHAPE.matcher(lowered).matches()
                || lowered.contains("discord.com/api/webhooks")
                || lowered.contains("hooks.slack.com")
                || lowered.contains("authorization:");
    }

    private static String summarize(String value) {
        String compact = value.replaceAll("\\s+", " ");
        return compact.length() > 96 ? compact.substring(0, 96) + "..." : compact;
    }
}

