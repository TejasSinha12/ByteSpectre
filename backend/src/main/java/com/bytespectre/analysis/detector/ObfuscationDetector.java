package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.bytecode.ClassBytecodeFacts;
import com.bytespectre.analysis.model.Indicator;
import java.util.ArrayList;
import java.util.List;

class ObfuscationDetector implements JarDetector {
    @Override
    public List<Indicator> detect(AnalysisContext context) {
        List<Indicator> indicators = new ArrayList<>();
        List<ClassBytecodeFacts> facts = context.classFacts();

        long shortClassNames = facts.stream().filter(fact -> simpleName(fact.className()).length() <= 2).count();
        if (facts.size() > 20 && shortClassNames > facts.size() * 0.35) {
            indicators.add(new Indicator("obfuscation.short-names", "Obfuscated class naming", "Obfuscation", 5, 82, shortClassNames + " very short class names", "A high ratio of one or two character class names often indicates name obfuscation."));
        }

        long encodedStrings = facts.stream()
                .flatMap(fact -> fact.stringConstants().stream())
                .filter(ObfuscationDetector::looksEncoded)
                .limit(100)
                .count();
        if (encodedStrings > 10) {
            indicators.add(new Indicator("strings.encoded", "Encoded string clusters", "Obfuscation", 4, 68, encodedStrings + " encoded-looking constants", "Repeated high-entropy string constants may indicate encrypted configuration, payloads, or string obfuscation."));
        }

        return indicators;
    }

    private static boolean looksEncoded(String value) {
        if (value.length() < 24) {
            return false;
        }
        int encodedChars = 0;
        for (char character : value.toCharArray()) {
            if (Character.isLetterOrDigit(character) || character == '+' || character == '/' || character == '=' || character == '_' || character == '-') {
                encodedChars++;
            }
        }
        return encodedChars / (double) value.length() > 0.92;
    }

    private static String simpleName(String className) {
        int split = className.lastIndexOf('.');
        return split >= 0 ? className.substring(split + 1) : className;
    }
}

