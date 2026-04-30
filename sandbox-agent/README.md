# ByteSpectre Sandbox Agent

The sandbox agent is the runtime telemetry boundary for ByteSpectre. It can be attached with `-javaagent` and currently emits class-load events for JVM, networking, instrumentation, Minecraft, modding, and bytecode tooling namespaces.

Build:

```bash
mvn package
```

Run against a sample artifact:

```bash
java -javaagent:target/bytespectre-sandbox-agent-0.1.0-SNAPSHOT.jar -jar /path/to/sample.jar
```

Next instrumentation targets:

- Socket connect tracing.
- Reflection invocation tracing.
- Thread creation tracing.
- Process execution detection.
- Event streaming to the Spring Boot API.

