# Elite Java

**Low-memory JVM experiments. Graal Native. HotSpot intrinsics.**

Java code that challenges the "enterprise bloat" stereotype. Each experiment maximizes performance and minimizes footprint using JVM tuning, off-heap memory, and native compilation.

## Featured

| Experiment | Footprint | Key Technique |
|------------|-----------|---------------|
| **No-GC Parser** | 4.2MB | Off-heap `ByteBuffer` → AST |
| **Native CLI** | 8MB | GraalVM Native Image, reflection-free |
| **SIMD Math** | 6.1MB | `VectorAPI` + intrinsic inlining |
| **Zero-Alloc Streams** | 5.8MB | `Spliterator` + primitive collections |

## Characteristics

- **Graal Native:** Sub-10MB standalone executables when possible
- **Footprint-first:** Heap usage ≤ 32MB target
- **HotSpot tuned:** `-XX:` flags + tiered compilation
- **No Spring:** Core Java 21+ only unless architecturally required
- **Benchmarked:** Inline JMH results vs Rust/C

## Philosophy

Java's strength is **mature optimization**. These experiments show how to:

Graal Native sub-10MB executables  
Zero-allocation parsing pipelines  
Vectorized math without JNI  
CLI tools that startup in 12ms

## Usage

```bash
# Standard JVM
./gradlew run

# Native (GraalVM)
./gradlew nativeCompile
./build/native/nativeCompile/experiment-name
```

## Benchmarks

| Experiment | Input Size | Java | Rust | Python |
|------------|------------|------|------|--------|
| JSON Parser | 1MB | 3.2ms | 2.1ms | 187ms |
| CLI Startup | - | 12ms | 89μs | 245ms |

**Newsletter** for Java deep-dives + weekly prompts: [PithyCyborg.com](https://PithyCyborg.com)

**X:** [@mrcomputersci](https://x.com/mrcomputersci) | [@pithycyborg](https://x.com/pithycyborg)

MIT License
