package com.bytespectre.sandbox;

import java.time.Instant;

final class SandboxEventSink {
    private final String destination;

    SandboxEventSink(String destination) {
        this.destination = destination;
    }

    void emit(String type, String message) {
        System.out.println("[ByteSpectreSandbox] " + Instant.now() + " type=" + type + " destination=" + destination + " " + message);
    }
}

