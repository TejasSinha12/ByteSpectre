package com.bytespectre.analysis.detector;

import com.bytespectre.analysis.bytecode.ClassBytecodeFacts;
import com.bytespectre.analysis.model.Indicator;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class NetworkSurfaceDetector implements JarDetector {
    private static final Pattern URL_PATTERN = Pattern.compile("(?i)\\bhttps?://[a-z0-9\\-._~%:/?#\\[\\]@!$&'()*+,;=]+");
    private static final Pattern WEBHOOK_PATTERN = Pattern.compile("(?i)https?://(?:canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d+/[a-z0-9_\\-]+");

    @Override
    public List<Indicator> detect(AnalysisContext context) {
        List<String> webhookEvidence = new ArrayList<>();
        List<String> urlEvidence = new ArrayList<>();

        for (ClassBytecodeFacts facts : context.classFacts()) {
            for (String constant : facts.stringConstants()) {
                if (constant == null || constant.isBlank() || constant.length() > 800) {
                    continue;
                }
                Matcher webhook = WEBHOOK_PATTERN.matcher(constant);
                if (webhook.find() && webhookEvidence.size() < 3) {
                    webhookEvidence.add(facts.className() + " :: " + summarize(webhook.group()));
                }
                Matcher url = URL_PATTERN.matcher(constant);
                while (url.find() && urlEvidence.size() < 5) {
                    String found = url.group();
                    if (looksLocal(found)) {
                        continue;
                    }
                    urlEvidence.add(facts.className() + " :: " + summarize(found));
                }
            }
        }

        List<Indicator> results = new ArrayList<>();
        if (!webhookEvidence.isEmpty()) {
            results.add(new Indicator(
                    "network.discord-webhook",
                    "Hardcoded Discord webhook endpoint",
                    "Networking",
                    8,
                    90,
                    String.join(", ", webhookEvidence),
                    "Discord webhooks are frequently abused for data exfiltration, command-and-control signals, or telemetry. Treat hardcoded webhook endpoints as high-risk until verified."
            ));
        }
        if (!urlEvidence.isEmpty()) {
            results.add(new Indicator(
                    "network.hardcoded-endpoints",
                    "Hardcoded network endpoints",
                    "Networking",
                    6,
                    72,
                    String.join(", ", urlEvidence),
                    "String constants include external URL endpoints. This can be benign (update checks, APIs) or malicious (C2, payload download). Review destinations and callsites."
            ));
        }
        return results;
    }

    private static boolean looksLocal(String url) {
        String lowered = url.toLowerCase(Locale.ROOT);
        return lowered.contains("localhost")
                || lowered.contains("127.0.0.1")
                || lowered.contains("[::1]")
                || lowered.contains("0.0.0.0");
    }

    private static String summarize(String value) {
        String compact = value.replaceAll("\\s+", " ").trim();
        return compact.length() > 96 ? compact.substring(0, 96) + "..." : compact;
    }
}

